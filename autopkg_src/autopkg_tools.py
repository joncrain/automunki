#!/usr/bin/env python3

# BSD-3-Clause
# Copyright (c) Facebook, Inc. and its affiliates.
# Copyright (c) tig <https://6fx.eu/>.
# Copyright (c) Gusto, Inc.
# Copyright 2023 Kandji, Inc.
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
from fnmatch import fnmatch
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
from cache_utils import load_cached_attributes, create_file_and_attributes


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
        _, err, exit_code = run_cmd(cmd)
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
        output, _, _ = run_cmd(cmd)
        logging.debug(f"Output: {output}")
        return

    def _get_pkg_version_from_receipt(self, new_dl):
        """Some processors don't return summary results with version/pkg_path
        This func will attempt to locate a receipt newer than the located DL
        and extract both version and pkg_path details for Slack notification"""
        # Set receipt pkg + version to None to return if we can't derive our version below
        receipt_pkg = None
        receipt_version = None
        # Get modification time of new DMG download
        dl_mod_time = os.path.getmtime(new_dl)
        # Get cache dir for build
        parent_path = Path(new_dl).parents[1]

        logging.debug(f"Trying to get receipt data from provided DL {new_dl}")

        # Check if receipts dir exists
        if os.path.exists(os.path.join(parent_path, "receipts")):
            for receipt in os.scandir(os.path.join(parent_path, "receipts")):
                # If we find a receipt with a newer mod time than our download, likely the receipt for our new build
                if os.path.getmtime(receipt) > dl_mod_time:
                    logging.debug(f"Found new receipt at {receipt}")
                    receipt_plist = _plist_pal(receipt)
                    logging.debug(f"Read in plist with contents {receipt_plist}")
                    try:
                        # Get "version" value from receipts plist and assign
                        receipt_version = [
                            values.get("version")
                            for plist in receipt_plist
                            for values in plist.values()
                            if isinstance(values, dict) and "version" in values.keys()
                        ][-1]
                        logging.debug(f"Found {receipt_version}")
                    except IndexError:
                        continue
                    try:
                        # Get "pkg_path" value from receipts plist and assign
                        receipt_pkg = [
                            values.get("pkg_path")
                            for plist in receipt_plist
                            for values in plist.values()
                            if isinstance(values, dict) and "pkg_path" in values.keys()
                        ][-1]
                    except IndexError:
                        continue
        return receipt_pkg, receipt_version

    def _parse_report(self, report):
        report_data = _plist_pal(report)
        failed_items = report_data.get("failures", [])
        downloaded_items = []
        built_items = []
        # If True, this means something happened
        if report_data.get("summary_results"):
            # Wildcard search for "pkg" in results to get key name since there are multiple possibilities
            pkg_summary_key = "".join(
                [
                    x
                    for x in report_data["summary_results"].keys()
                    if fnmatch(x, "*pkg*")
                ]
            )
            pkg_results = report_data.get("summary_results").get(pkg_summary_key, {})
            built_items.extend(pkg_results.get("data_rows", []))
            dl_results = report_data.get("summary_results").get(
                "url_downloader_summary_result", {}
            )
            downloaded_items.extend(dl_results.get("data_rows", []))
            # There are some cases where a new package was built, but processors like FlatPkgPacker don't show in results
            if dl_results and not pkg_results:
                # If so, look at the download path and identify if the DL'd file was a pkg and report it like a build
                if fringe_build := "".join(
                    [
                        next(iter(x.values()))
                        for x in dl_results.get("data_rows")
                        if fnmatch(next(iter(x.values())), "*pkg*")
                    ]
                ):
                    receipt_pkg, receipt_version = self._get_pkg_version_from_receipt(
                        fringe_build
                    )

                    # Append pkg_path and version if values are not None
                    # Elif append download as pkg_path and version if populated
                    # Else append download as pkg_path and version will be Unknown
                    if receipt_pkg and receipt_version:
                        built_items.append(
                            {"pkg_path": receipt_pkg, "version": receipt_version}
                        )
                    elif receipt_version:
                        logging.debug("Appending built items with version")
                        built_items.append(
                            {"pkg_path": fringe_build, "version": receipt_version}
                        )
                    else:
                        built_items.append({"pkg_path": fringe_build})

        return {
            "built": built_items,
            "downloaded": downloaded_items,
            "failed": failed_items,
        }

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
            "--post",
            "io.kandji.cachedata/CacheRecipeMetadata",
            "--report-plist",
            report_path,
        ]
        output, err, _ = run_cmd(cmd)
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
        # create_pull_request(munki_repo, title, body, branch_name)
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


def _plist_pal(path):
    """Function accepts argument of path to .plist file as `path`
    Returns plist formatted as dict"""
    with open(path, "rb") as f:
        loaded_plist = plistlib.load(f)
        return loaded_plist


def main():
    parser = ArgumentParser(description="Wrap AutoPkg with git support.")
    parser.add_argument(
        "-l", "--list", help="Path to a plist or JSON list of recipe names."
    )
    parser.add_argument(
        "-c",
        "--cache",
        action="store_true",
        required=False,
        default=False,
        help="Load and write previously cached metadata/xattrs for comparison; save out new metadata post-run.",
    )
    args = parser.parse_args()

    action_recipe = os.environ.get("RECIPE", None)

    recipes = (
        action_recipe.split(", ") if action_recipe else args.list if args.list else None
    )

    if recipes is None:
        logging.fatal("Recipe --list or RECIPE not provided!")
        sys.exit(1)
    if args.cache:
        attributes_dict = load_cached_attributes("/private/tmp/autopkg_metadata.json")
        create_file_and_attributes(attributes_dict)

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
