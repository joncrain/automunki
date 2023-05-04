#!/usr/bin/env python3

# BSD-3-Clause
# Copyright (c) Facebook, Inc. and its affiliates.
# Copyright (c) tig <https://6fx.eu/>.
# Copyright (c) Gusto, Inc.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import json
import logging
import os
import plistlib
import requests
import shutil
import subprocess
import sys
import threading
from datetime import datetime
from optparse import OptionParser
from pathlib import Path

import git

SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_TOKEN", None)
RECIPE_TO_RUN = os.environ.get("RECIPE", None)

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


class Recipe(object):
    def __init__(self, path):
        self.path = os.path.join("autopkg_src/overrides", path)
        self.error = False
        self.results = {}
        self.updated = False
        self.verified = None

        self._keys = None
        self._has_run = False

    @property
    def plist(self):
        if self._keys is None:
            with open(self.path, "rb") as f:
                self._keys = plistlib.load(f)

        return self._keys

    @property
    def branch(self):
        return (
            "{}_{}".format(self.name, self.updated_version)
            .strip()
            .replace(" ", "")
            .replace(")", "-")
            .replace("(", "-")
        )

    @property
    def updated_version(self):
        if not self.results or not self.results["imported"]:
            return None

        return self.results["imported"][0]["version"].strip().replace(" ", "")

    @property
    def name(self):
        return self.plist["Input"]["NAME"]

    def verify_trust_info(self):
        cmd = ["/usr/local/bin/autopkg", "verify-trust-info", self.path, "-vvv"]
        output, err, exit_code = run_cmd(cmd)
        if exit_code == 0:
            self.verified = True
        else:
            err = err.decode()
            self.results["message"] = err
            self.verified = False
        return self.verified

    def update_trust_info(self):
        cmd = ["/usr/local/bin/autopkg", "update-trust-info", self.path]
        output, err, exit_code = run_cmd(cmd)
        return output

    def _parse_report(self, report):
        with open(report, "rb") as f:
            report_data = plistlib.load(f)

        failed_items = report_data.get("failures", [])
        imported_items = []
        if report_data["summary_results"]:
            # This means something happened
            munki_results = report_data["summary_results"].get(
                "munki_importer_summary_result", {}
            )
            imported_items.extend(munki_results.get("data_rows", []))

        return {"imported": imported_items, "failed": failed_items}

    def run(self):
        if self.verified == False:
            self.error = True
            self.results["failed"] = True
            self.results["imported"] = ""
        else:
            report = f"/tmp/{self.name}.plist"
            if not os.path.isfile(report):
                # Letting autopkg create them has led to errors on github runners
                Path(report).touch()
            cmd = [
                "/usr/local/bin/autopkg",
                "run",
                self.path,
                "-v",
                "--post",
                "io.github.hjuutilainen.VirusTotalAnalyzer/VirusTotalAnalyzer",
                "--report-plist",
                report,
            ]
            output, err, exit_code = run_cmd(cmd)
            if err:
                self.error = True
                self.results["failed"] = True
                self.results["imported"] = ""
            self._has_run = True
            self.results = self._parse_report(report)
            if not self.results["failed"] and not self.error and self.updated_version:
                self.updated = True
        return self.results


def run_cmd(cmd):
    logging.debug(f"Running { ' '.join(cmd)}")
    run = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = run.communicate()
    exit_code = run.wait()
    return output, err, exit_code


def create_pull_request(repo, title, body, head, base="main"):
    payload = {
        "title": title,
        "body": body,
        "head": head,
        "base": base,
    }
    url = f"https://api.github.com/repos/{repo}/pulls"
    headers = {
        "Authorization": f"token {os.environ['GH_TOKEN']}",
        "Accept": "application/vnd.github.v3+json",
    }
    json_payload = json.dumps(payload)
    response = requests.post(url, headers=headers, data=json_payload)
    return response.json()


def worktree_add(repo, branch):
    """Add a worktree for the branch and return the repo object"""
    logging.debug(f"Adding worktree for {branch}")
    repo.git.worktree("add", branch, "-b", branch)
    worktree_repo = git.Repo(os.path.join(repo.working_dir, branch))
    worktree_repo.git.fetch()
    if branch in repo.git.branch("--list", "-r"):
        worktree_repo.git.pull("origin", branch)
    return worktree_repo


def worktree_commit(repo, branch, file_changes, commit_message):
    """Commit changes to a worktree and push to origin"""
    worktree_repo = worktree_add(repo, branch)
    logging.debug(f"Committing {file_changes} to {branch}")
    for file_change in file_changes:
        logging.debug(
            f"Copying {file_change} from {repo.working_dir} to {worktree_repo.working_dir}"
        )
        shutil.copy(
            f"{repo.working_dir}/{file_change}",
            f"{worktree_repo.working_dir}/{file_change}",
        )
        worktree_repo.index.add([f"{worktree_repo.working_dir}/{file_change}"])
    worktree_repo.index.commit(commit_message)
    worktree_repo.git.push("--set-upstream", "origin", branch)
    repo.git.worktree("remove", branch, "-f")


def handle_recipe(recipe):
    logging.debug(f"Handling {recipe.name}")
    repo = os.environ.get("GITHUB_REPOSITORY", None)
    munki_repo = git.Repo(os.getenv("GITHUB_WORKSPACE", "./"))
    recipe.verify_trust_info()
    if recipe.verified is False:
        logging.debug(f"Updating trust for {recipe.name}")
        recipe.update_trust_info()
        branch_name = (
            f"update_trust-{recipe.name}-{datetime.now().strftime('%Y-%m-%d')}"
        )
        worktree_commit(
            munki_repo, branch_name, [recipe.path], f"Update trust for {recipe.name}"
        )
        title = (f"feat: Update trust for { recipe.name }",)
        body = (recipe.results["message"],)
        create_pull_request(repo, title, body, branch_name)
    if recipe.verified in (True, None):
        recipe.run()
        if recipe.results["imported"]:
            print("Imported")
            pkg_info_path = os.path.join(
                "pkgsinfo", recipe.results["imported"][0]["pkginfo_path"]
            )
            worktree_commit(
                munki_repo,
                recipe.branch,
                [pkg_info_path],
                f"'Updated { recipe.name } to { recipe.updated_version }'",
            )

            title = f"feat: Update { recipe.name } to { recipe.updated_version }"
            body = f"Updated { recipe.name } to { recipe.updated_version }"
            create_pull_request(repo, title, body, recipe.branch)
    # slack_alert(recipe, opts)
    return


def parse_recipes(recipes):
    recipe_list = []
    if RECIPE_TO_RUN:
        for recipe in recipes:
            ext = os.path.splitext(recipe)[1]
            if ext != ".recipe":
                recipe_list.append(f"{recipe}.recipe")
            else:
                recipe_list.append(recipe)
    else:
        ext = os.path.splitext(recipes)[1]
        if ext == ".json":
            parser = json.load
        elif ext == ".plist":
            parser = plistlib.load
        else:
            print(f'Invalid run list extension "{ ext }" (expected plist or json)')
            sys.exit(1)
        with open(recipes, "rb") as f:
            recipe_list = parser(f)
    return map(Recipe, recipe_list)


def main():
    parser = OptionParser(description="Wrap AutoPkg with git support.")
    parser.add_option(
        "-l", "--list", help="Path to a plist or JSON list of recipe names."
    )

    (opts, _) = parser.parse_args()

    recipes = (
        RECIPE_TO_RUN.split(", ") if RECIPE_TO_RUN else opts.list if opts.list else None
    )

    if recipes is None:
        print("Recipe --list or RECIPE_TO_RUN not provided!")
        sys.exit(1)
    recipes = parse_recipes(recipes)
    threads = []

    for recipe in recipes:
        # handle_recipe(recipe, opts)
        thread = threading.Thread(target=handle_recipe(recipe))
        threads.append(thread)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
