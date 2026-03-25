# Local AutoPkg runner

AutoMunki can trigger AutoPkg in **GitHub Actions** (default) or register a run for a **Mac you control** (local runner). Local runs do not call the GitHub API; you execute the same steps the [`autopkg_cloud_runner.yml`](../.github/workflows/autopkg_cloud_runner.yml) workflow runs, pointed at your AutoMunki API.

## Quick start (script)

From your automunki clone, after you trigger **Local Mac** in the UI and copy the run UUID:

```bash
./AutoPkg/scripts/run_local_autopkg.sh \
  --backend-url "https://your-api.example.com" \
  --run-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Optional arguments:

| Flag | Meaning |
|------|---------|
| `-w`, `--workspace` | Path to repo root (default: inferred from script location) |
| `--recipes` | Comma-separated recipe names (same as UI subset) |
| `-t`, `--token` | JWT if your API requires `Authorization: Bearer` (also sets `AUTOMUNKI_API_TOKEN` for Python) |
| `--keep-temps` | Keep run scratch files (see below); default is to delete them when the script exits |
| `--autopkg-force` | Run **`autopkg run --force`** for each recipe instead of `cloud-autopkg-runner` (see troubleshooting) |

By default, the script **removes temporary files** when it finishes (success or failure): `metadata_cache_response.json`, `metadata_cache.json`, `run_config.json`, `autopkg_runner.log`, `AutoPkg/run_recipe_list.json`, `AutoPkg/run_repo_list.txt`, and `AutoPkg/Reports/*.plist`. Override plists under `AutoPkg/Overrides/` are **not** deleted (they are rewritten from the API on the next run). Use `--keep-temps` to debug a failed run.

One-time AutoPkg `defaults` on this Mac:

```bash
./AutoPkg/scripts/run_local_autopkg.sh --setup-defaults
# optional: pass a GitHub token for recipes that use the GitHub processor
./AutoPkg/scripts/run_local_autopkg.sh --setup-defaults --github-token "ghp_..."
```

Use `-w` with `--setup-defaults` if the repo is not next to the default path.

Full reference: `./AutoPkg/scripts/run_local_autopkg.sh --help`

## Automated daemon (no manual command)

If you set **`LOCAL_RUNNER_TOKEN`** on the AutoMunki server (same value in `.env` as `openssl rand -hex 32`), the API accepts that token as `Authorization: Bearer …` for the local runner endpoints (claim, metadata cache, run config). A Mac that runs AutoPkg can then loop with **`poll_local_autopkg.sh`**, which:

1. `POST /api/v1/autopkg/runs/claim-next-local` — if **204**, nothing is queued; wait and retry.
2. If **200**, read `id` from the JSON body and invoke `run_local_autopkg.sh` with `--run-id` (same token for curl/Python).

**Server**

```bash
# In the repo root .env (or Docker env for `backend`)
LOCAL_RUNNER_TOKEN=<long-random-secret>
```

Restart the backend. The token is only checked for specific paths (see [API reference](api-reference.md)).

**Runner Mac**

```bash
export AUTOMUNKI_BACKEND_URL=https://your-automunki.example.com
export LOCAL_RUNNER_TOKEN=<same-as-server>
./AutoPkg/scripts/poll_local_autopkg.sh --backend-url "$AUTOMUNKI_BACKEND_URL" --token "$LOCAL_RUNNER_TOKEN"
```

Optional: `--workspace /path/to/automunki`, `--interval 30` (seconds between polls when idle).

**UI:** In the AutoPkg run dialog, choose **Local Mac (automated daemon)** so the success toast does not expect you to copy a shell command. **Local Mac (copy shell command)** keeps the previous behavior.

**launchd (stay running after login)**

Use a LaunchAgent that sets `AUTOMUNKI_BACKEND_URL` and `LOCAL_RUNNER_TOKEN` (or read the token from Keychain with `security find-generic-password -s automunki-local-runner -w`). Run `poll_local_autopkg.sh` with `RunAtLoad` and `KeepAlive`.

**Note:** You can still use a normal **user JWT** with `run_local_autopkg.sh` instead of `LOCAL_RUNNER_TOKEN`; the daemon path is for machines that should not store a user password.

## When to use a local runner

- You want builds on an internal Mac without GitHub-hosted minutes or workflow limits.
- Recipes need resources or network access that CI cannot provide.
- You are developing or debugging AutoPkg and want a tight loop on one machine.

`uv` / `uvx` in CI only isolates the **cloud-autopkg-runner** Python tool. It does not sandbox AutoPkg itself; a local runner still needs **AutoPkg** and **Munki tools** installed on that Mac (see below).

## UI: GitHub vs local

1. Open **Settings** — the server default is shown (`AUTOPKG_RUNNER_MODE` in `.env`).
2. On **AutoPkg → Runs** (or the recipe quick-run dialog), choose **Runner**:
   - **GitHub Actions**
   - **Local Mac (copy shell command)** — toast shows `./AutoPkg/scripts/run_local_autopkg.sh …`
   - **Local Mac (automated daemon)** — for `poll_local_autopkg.sh` + `LOCAL_RUNNER_TOKEN`; no command to copy
3. Your choice is remembered in the browser for the next trigger.

- **GitHub Actions**: the API creates an `autopkg_run` and dispatches `autopkg_cloud_runner.yml` (requires `GITHUB_TOKEN` and `GITHUB_REPO` on the server).
- **Local Mac** (both variants): the API creates an `autopkg_run` with status **pending** and `runner_type` **local**. Either run **`poll_local_autopkg.sh`** (automated) or **`run_local_autopkg.sh`** with the run `id` (manual), or follow [manual steps](#manual-steps-same-as-the-script) below.

## Prerequisites on the local Mac

| Requirement | Purpose |
|-------------|---------|
| macOS | AutoPkg and most processors assume a Mac. |
| [AutoPkg](https://github.com/autopkg/autopkg/releases) | `autopkg` CLI. |
| [Munki](https://github.com/munki/munki/releases) | MunkiImporter / `makepkginfo` for `.munki.recipe` flows. |
| [uv](https://docs.astral.sh/uv/) | Used to run `uvx cloud-autopkg-runner` (same as CI). |
| Git | `autopkg repo-add` clones recipe repos. |
| Clone of this repo | Contains `AutoPkg/scripts/` and layout expected by scripts. |

The AutoMunki **API** must be reachable from that Mac (same URL as `API_PUBLIC_URL` / your tunnel).

## Manual steps (same as the script)

The script [`AutoPkg/scripts/run_local_autopkg.sh`](../AutoPkg/scripts/run_local_autopkg.sh) automates the following. Use this section only if you need to run pieces by hand.

### One-time AutoPkg preferences

Equivalent to `./AutoPkg/scripts/run_local_autopkg.sh --setup-defaults` (and optional `--github-token`):

```bash
export GITHUB_WORKSPACE="/path/to/automunki"
mkdir -p "$GITHUB_WORKSPACE/pkgs" "$GITHUB_WORKSPACE/AutoPkg/Overrides" \
  "$GITHUB_WORKSPACE/AutoPkg/repos" "$GITHUB_WORKSPACE/AutoPkg/Reports" \
  "$GITHUB_WORKSPACE/AutoPkg/Cache" "$HOME/Library/AutoPkg"

defaults write com.github.autopkg CACHE_DIR "$GITHUB_WORKSPACE/AutoPkg/Cache"
defaults write com.github.autopkg RECIPE_OVERRIDE_DIRS "$GITHUB_WORKSPACE/AutoPkg/Overrides/"
defaults write com.github.autopkg RECIPE_REPO_DIR "$GITHUB_WORKSPACE/AutoPkg/repos/"
defaults write com.github.autopkg FAIL_RECIPES_WITHOUT_TRUST_INFO -bool TRUE
defaults write com.github.autopkg MUNKI_REPO "$GITHUB_WORKSPACE"
# Optional: for recipes that use the GitHub processor
defaults write com.github.autopkg GITHUB_TOKEN "ghp_..."
```

### Run pipeline (after a local run is registered)

Set `GITHUB_WORKSPACE`, `BACKEND_URL` (no `/api/v1`), `RUN_ID`, and optionally `RECIPE_FILTER`, then run the same blocks as in the script: metadata cache → `runs/config` + `write_overrides.py` → `autopkg repo-add` / `repo-update` → `uvx cloud-autopkg-runner` → `save_metadata_cache.py` → `report_results.py` per plist → `POST .../complete`.

## Troubleshooting

- **`no_change` / “not newer” even after truncating `autopkg_metadata_cache_entry`**: The database cache is only what **`cloud-autopkg-runner`** uses to fake downloaded files in CI. **MunkiImporter** (inside AutoPkg) compares the **new** pkginfo against what is already on disk under **`MUNKI_REPO/pkgsinfo/`** (your repo root when using `--setup-defaults`). If a plist for Adobe Reader / Acrobat is still there with the **same version** the recipe would import, AutoPkg reports **no_change** — clearing Postgres does not change that. **Fix (pick one):**
  1. **Remove the pkginfo plist(s)** from `pkgsinfo/` (search for the app name, e.g. `ls pkgsinfo | grep -i reader`), then run the normal script again.
  2. **Force a full recipe run** so AutoPkg ignores the “not newer” check: add **`--autopkg-force`** to `run_local_autopkg.sh`. That runs `autopkg run <recipe> --force` for each recipe in the run list (sequential, bypasses `cloud-autopkg-runner`). Use when you intentionally want to re-import the current upstream version.
- **DB metadata cache (optional)**: If you still see odd download/skip behavior after fixing `pkgsinfo`, clear AutoMunki’s runner cache for that recipe (or all): `DELETE /api/v1/autopkg/metadata-cache?recipe_key=AdobeReader.munki.recipe` (see [API reference](api-reference.md)). Keys match override filenames like `AdobeReader.munki.recipe`.
- **AutoPkg processor cache**: If a processor keeps skipping work, remove the relevant receipts under **`AutoPkg/Cache/`** (or the whole `AutoPkg/Cache` tree for a blunt reset).

- **`Permission denied: '/Users/runner'`** (or paths under `/Users/runner/work/...`): The metadata cache stored in AutoMunki still had absolute paths from **GitHub Actions** (`GITHUB_WORKSPACE` on the hosted runner). `cloud-autopkg-runner` replays those paths locally. Ensure **`GITHUB_WORKSPACE`** is set to your local repo root before `load_metadata_cache.py` runs (the [`run_local_autopkg.sh`](../AutoPkg/scripts/run_local_autopkg.sh) script exports it). The loader rewrites `/Users/runner/work/<owner>/<repo>` prefixes to your workspace. If you fetched the cache manually, run from the repo root with `export GITHUB_WORKSPACE="$(pwd)"` or delete `metadata_cache.json` and use an empty cache once.
- **`401` / auth errors**: pass `-t` / `--token` (or `AUTOMUNKI_API_TOKEN`) so curl and Python requests send a Bearer token.
- **Trust blocked recipes**: the API omits them from `/runs/config` until trust is verified — same as GitHub Actions.
- **MUNKI_REPO**: must be writable; recipes import pkginfo under `pkgsinfo/` relative to that repo path.

## Environment reference

| Variable | Meaning |
|----------|---------|
| `AUTOPKG_RUNNER_MODE` | Server default: `github` or `local` (when the UI does not send `runner`). |
| `API_PUBLIC_URL` | Used when dispatching GitHub Actions so the workflow can call back to your API. |
| `GITHUB_TOKEN` / `GITHUB_REPO` | Required on the **server** only for **GitHub** runner mode. |
| `AUTOMUNKI_API_TOKEN` | Optional; same as `--token` for local script Python `urllib` calls. |
| `LOCAL_RUNNER_TOKEN` | **Server:** shared secret so the daemon can authenticate without a user JWT. **Client:** same value in `Authorization: Bearer` for `poll_local_autopkg.sh` / `run_local_autopkg.sh` when not using a JWT. |
