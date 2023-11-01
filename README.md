# automunki

A munki repo that automatically updates itself.

## Requirements

Create a PAT at https://github.com/settings/tokens and store in the Repository secrets as `RW_REPO_TOKEN`.

## Usage

Currently this will only run on a manual dispatch from Github Actions. However a cron schedule can be added to the workflow to run on a schedule. Example:

```yaml
on:
  schedule:
    - cron:  '0 0 * * *'
  workflow_dispatch:
...
```

### Running recipes

Recipes can be run by adding a `run_recipe` input to the workflow dispatch or by editing the `recipe_list.json` file in the repo. The `run_recipe` input will take precedence over the `recipe_list.json` file.

Be sure the that `repo_list.txt` file is updated with the repo you want to run the recipe against and that a proper override for the recipe is in the `overrides` directory.

### Storing binaries

This wrapper does not store the binaries in the repo. Instead it is up to the user to add a final step to the `autopkg.yml` file to sync to a storage bucket (i.e. S3, Azure Blob, etc.)

Test automerge.
