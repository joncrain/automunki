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
import json
import logging
import os
import plistlib
import subprocess
import sys
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path

import git
import psutil

SLACK_WEBHOOK = os.environ.get("SUMMARY_WEBHOOK_TOKEN", None)
SUMMARY_WEBHOOK = os.environ.get("SUMMARY_WEBHOOK_TOKEN", None)
MUNKI_WEBSITE = os.environ.get("MUNKI_WEBSITE", "munki.example.com")

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(module)-20s %(levelname)-8s %(message)s",
    datefmt="%m-%d %H:%M",
    filename=f"/var/tmp/autopkg/autopkg.log",
    filemode="w",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(module)-20s: %(levelname)-8s %(message)s")
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)

from git_utils import create_pull_request, worktree_commit
from slack_utils import slack_alert, slack_recipe_block, slack_summary_block


class Recipe(object):
    def __init__(self, path):
        self.path = os.path.join("autopkg_src/overrides", path)
        self.error = False
        self.results = {"imported": [], "failed": []}
        self.updated = False
        self.verified = False

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
            f"autopkg-{self.name}_{self.updated_version}".strip()
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
            logging.info(f"Verified trust info for {self.name}")
            self.verified = True
        else:
            logging.info(f"Verify trust info failed for {self.name}")
            err = err.decode()
            self.results["message"] = err
        return self.verified

    def update_trust_info(self):
        logging.info(f"Updating trust info for {self.name}")
        cmd = ["/usr/local/bin/autopkg", "update-trust-info", self.path]
        output, err, exit_code = run_cmd(cmd)
        logging.debug(f"Output: {output}")
        return

    def _parse_report(self, report):
        with open(report, "rb") as f:
            report_data = plistlib.load(f)
        failed_items = report_data.get("failures", [])
        imported_items = []
        if report_data["summary_results"]:
            munki_results = report_data["summary_results"].get(
                "munki_importer_summary_result", {}
            )
            imported_items.extend(munki_results.get("data_rows", []))
        return {"imported": imported_items, "failed": failed_items}

    def run(self):
        logging.info(f"Running {self.name}")
        logging.info(f"The current cpu percent is {psutil.cpu_percent(4)}%")
        report_path = f"/var/tmp/autopkg/{self.name}.plist"
        Path(report_path).touch()
        cmd = [
            "/usr/local/bin/autopkg",
            "run",
            self.path,
            "-vvvvv",
            "--post",
            "io.github.hjuutilainen.VirusTotalAnalyzer/VirusTotalAnalyzer",
            "--report-plist",
            report_path,
        ]
        output, err, exit_code = run_cmd(cmd)
        logging.debug(f"Output: {output.decode()}")
        if err:
            logging.info(f"Error running {self.name}: {err.decode()}")
            self.error = True
            self.results = {"failed": True, "imported": ""}
        logging.info(f"Finished running {self.name}")
        self._has_run = True
        self.results = self._parse_report(report_path)
        if self.updated_version and not self.error and not self.results["failed"]:
            self.updated = True
        return self.results


def run_cmd(cmd):
    logging.debug(f"Running { ' '.join(cmd)}")
    run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    logging.debug(f"Stdout: {run.stdout.decode()}")
    logging.debug(f"Stderr: {run.stderr.decode()}")
    return run.stdout, run.stderr, run.returncode


def handle_recipe(recipe):
    logging.info(f"Handling {recipe.name}")
    repo = os.environ.get("GITHUB_REPOSITORY", None)
    munki_repo = git.Repo(os.getenv("GITHUB_WORKSPACE", "./"))
    recipe.verify_trust_info()
    if recipe.verified:
        recipe.run()
        if recipe.results["imported"]:
            file_changes = []
            for item in recipe.results["imported"]:
                pkg_info_path = os.path.join("pkgsinfo", item["pkginfo_path"])
                logging.info(f"Adding {pkg_info_path} to commit")
                file_changes.append(pkg_info_path)
            worktree_commit(
                munki_repo,
                recipe.branch,
                file_changes,
                f"'Updated { recipe.name } to { recipe.updated_version }'",
            )

            title = f"feat: Update { recipe.name } to { recipe.updated_version }"
            body = f"Updated { recipe.name } to { recipe.updated_version }"
            create_pull_request(munki_repo, title, body, recipe.branch)
    else:
        logging.info(f"Updating trust for {recipe.name}")
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
    slack_payload = slack_recipe_block(recipe, MUNKI_WEBSITE)
    if slack_payload:
        slack_alert(slack_payload, SLACK_WEBHOOK)
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
        logging.error("Recipe --list or RECIPE not provided!")
        sys.exit(1)

    recipes = parse_recipes(recipes, action_recipe)
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(handle_recipe, recipe) for recipe in recipes]
        for future in concurrent.futures.as_completed(futures):
            try:
                recipe_result = future.result()
                if recipe_result.results["imported"]:
                    results[recipe_result.name] = recipe_result.updated_version
            except Exception as exc:
                logging.warning(f"Recipe execution failed: {exc}")
    if results:
        slack_alert(slack_summary_block(results), SUMMARY_WEBHOOK)


if __name__ == "__main__":
    main()
