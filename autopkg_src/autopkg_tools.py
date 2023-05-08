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

import concurrent.futures
import contextlib
import json
import logging
import os
import plistlib
import requests
import shutil
import subprocess
import sys
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path
from time import time
from urllib.parse import urljoin


import git

SUMMARY_WEBHOOK_TOKEN = os.environ.get("SUMMARY_WEBHOOK_TOKEN", None)

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


class Recipe(object):
    def __init__(self, path):
        self.path = os.path.join("autopkg_src/overrides", path)
        self.error = False
        self.results = {"imported": [], "failed": []}
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
    run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return run.stdout, run.stderr, run.returncode


def create_pull_request(repo, title, body, head, base="main"):
    remote_url = repo.remotes.origin.url
    parts = remote_url.split("/")
    organization = parts[-2].replace(".git", "")
    name = parts[-1]
    payload = {
        "title": title,
        "body": body,
        "head": head,
        "base": base,
    }
    url = urljoin(f"https://api.github.com/repos/{organization}/{name}/", "pulls")
    headers = {
        "Authorization": f"token {os.environ['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.post(url, headers=headers, json=payload)
    return response.json()


def worktree_commit(repo, branch, file_changes, commit_message):
    """Commit changes to a worktree and push to origin"""
    logging.debug(f"Adding worktree for {branch}")
    repo.git.worktree("add", branch, "-b", branch)
    worktree_path = Path(repo.working_dir) / branch
    worktree_repo = git.Repo(worktree_path)
    worktree_remote = worktree_repo.remotes[0].name
    worktree_repo.git.fetch()
    if branch in repo.git.branch("--list", "-r"):
        worktree_repo.git.push(worktree_remote, "--delete", branch)
    logging.debug(f"Committing {file_changes} to {branch}")
    for file_change in file_changes:
        src_path = Path(repo.working_dir) / file_change
        dest_path = worktree_path / file_change
        logging.debug(f"Copying {src_path} to {dest_path}")
        shutil.copy(src_path, dest_path)
        worktree_repo.index.add([dest_path])
    worktree_repo.index.commit(commit_message)
    worktree_repo.git.push("--set-upstream", worktree_remote, branch)
    with contextlib.suppress(Exception):
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
        title = f"feat: Update trust for { recipe.name }"
        body = recipe.results["message"]
        create_pull_request(munki_repo, title, body, branch_name)
    if recipe.verified in (True, None):
        recipe.run()
        if recipe.results["imported"]:
            logging.info(f"Imported {recipe.name} {recipe.updated_version}")
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
            create_pull_request(munki_repo, title, body, recipe.branch)
    # slack_alert(recipe, opts)
    return recipe


def parse_recipes(recipes, action_recipe=None):
    if action_recipe:
        r_list = [r + ".recipe" if not r.endswith(".recipe") else r for r in recipes]
    else:
        ext = os.path.splitext(recipes)[1]
        if ext == ".json":
            parser = json.load
        elif ext == ".plist":
            parser = plistlib.load
        else:
            raise ValueError(
                f'Invalid run list extension "{ext}" (expected plist or json)'
            )
        with open(recipes, "rb") as f:
            r_list = parser(f)
    return map(Recipe, r_list)


def slack_summary_block(applications):
    fields = [
        {"title": "Application", "short": True, "value": app}
        for app in applications.keys()
    ]
    fields += [
        {"title": "Version", "short": True, "value": version}
        for version in applications.values()
    ]
    block = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":new: The following items have been updated",
                    "emoji": True,
                },
            },
            {"type": "divider"},
        ],
        "attachments": [
            {
                "mrkdwn_in": ["text"],
                "color": "00FF00",
                "ts": time(),
                "fields": fields,
                "footer": "Autopkg Automated Run",
                "footer_icon": "https://avatars.slack-edge.com/2020-10-30/1451262020951_7067702535522f0c569b_48.png",
            }
        ],
    }
    return block


def slack_alert(data, url):
    if not url:
        print("Skipping Slack notification - webhook is missing!")
        return

    byte_length = str(sys.getsizeof(data))
    headers = {"Content-Type": "application/json", "Content-Length": byte_length}

    response = requests.post(url, data=json.dumps(data), headers=headers)
    if response.status_code != 200:
        logging.warning(
            f"WARNING: Request to slack returned an error {response.status_code}, the response is:\n{response.text}"
        )


def main():
    parser = ArgumentParser(description="Wrap AutoPkg with git support.")
    parser.add_argument(
        "-l", "--list", help="Path to a plist or JSON list of recipe names."
    )
    args = parser.parse_args()

    action_recipe = os.environ.get("RECIPE", None)

    recipes = (
        action_recipe.split(", ") if action_recipe else args.list if args.list else None
    )

    if recipes is None:
        logging.fatal("Recipe --list or RECIPE not provided!")
        sys.exit(1)

    recipes = parse_recipes(recipes, action_recipe)
    results = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(handle_recipe, recipe) for recipe in recipes]
        for future in concurrent.futures.as_completed(futures):
            try:
                recipe_result = future.result()
                logging.info(recipe_result)
                results[recipe_result.name] = recipe_result.updated_version
            except Exception as exc:
                logging.warning(f"Recipe execution failed: {exc}")
    if results:
        slack_alert(slack_summary_block(results), SUMMARY_WEBHOOK_TOKEN)


if __name__ == "__main__":
    main()
