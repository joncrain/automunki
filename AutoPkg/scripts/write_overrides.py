"""Read run_config.json and write override plists, recipe list, and repo list."""

import json
import os
import plistlib

with open("run_config.json") as f:
    config = json.load(f)

override_dir = os.path.join(os.environ["GITHUB_WORKSPACE"], "AutoPkg", "Overrides")
os.makedirs(override_dir, exist_ok=True)

recipe_names: list[str] = []
for override in config.get("overrides", []):
    name = override["name"]
    plist_data = override.get("plist", {})
    filename = f"{name}.munki.recipe"
    filepath = os.path.join(override_dir, filename)

    with open(filepath, "wb") as f:
        plistlib.dump(plist_data, f)
    print(f"Wrote override: {filepath}")
    recipe_names.append(filename)

with open("AutoPkg/run_recipe_list.json", "w") as f:
    json.dump(recipe_names, f)
print(f"Recipe list: {recipe_names}")

repos = config.get("repos", [])
with open("AutoPkg/run_repo_list.txt", "w") as f:
    for repo in repos:
        f.write(repo + "\n")
print(f"Repo list ({len(repos)} repos): {repos}")
