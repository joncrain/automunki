#!/usr/bin/env zsh
# Local AutoPkg runner — same steps as docs/local-autopkg-runner.md and
# .github/workflows/autopkg_cloud_runner.yml
#
# Examples:
#   ./AutoPkg/scripts/run_local_autopkg.sh --backend-url https://app.example.com --run-id <uuid>
#   ./AutoPkg/scripts/run_local_autopkg.sh -b https://localhost:3000 -r <uuid> -w ~/src/automunki --recipes Firefox
#   ./AutoPkg/scripts/run_local_autopkg.sh -b https://localhost:3000 -r <uuid> --autopkg-force   # autopkg run --force
#   ./AutoPkg/scripts/run_local_autopkg.sh --setup-defaults
#   ./AutoPkg/scripts/run_local_autopkg.sh --setup-defaults --github-token ghp_xxx
# Fully automated (claim pending runs — see docs/local-autopkg-runner.md):
#   ./AutoPkg/scripts/poll_local_autopkg.sh -b https://app.example.com -t "$LOCAL_RUNNER_TOKEN"

set -euo pipefail

SCRIPT_PATH="${0:A}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
DEFAULT_WORKSPACE="$(cd "$SCRIPT_DIR/../.." && pwd)"

usage() {
  cat <<'EOF'
Usage: run_local_autopkg.sh --backend-url URL --run-id UUID [options]

  Run the full local pipeline after you trigger a "Local Mac" run in AutoMunki.

Required:
  -b, --backend-url URL   API origin (no /api/v1). Same as NEXT_PUBLIC_API_URL / API_PUBLIC_URL.
  -r, --run-id UUID       autopkg_run id from the Runs UI or API.

Optional:
  -w, --workspace PATH    automunki repo root (default: directory above AutoPkg/scripts)
      --recipes LIST      Comma-separated recipe names (subset), same as the UI filter
  -t, --token TOKEN       Bearer JWT if your API requires auth (also set AUTOMUNKI_API_TOKEN for Python)
      --keep-temps        Do not delete run scratch files (metadata cache, run_config, logs, reports)
      --autopkg-force     Run ``autopkg run --force`` per recipe instead of cloud-autopkg-runner (re-import / stuck no_change)

One-time AutoPkg defaults (macOS):
      --setup-defaults    Only create dirs and run defaults write; then exit
      --github-token T    With --setup-defaults: set com.github.autopkg GITHUB_TOKEN (optional)

  -h, --help              Show this help

Environment (optional):
  AUTOMUNKI_API_TOKEN     Same as --token; passed to Python urllib calls

EOF
}

BACKEND_URL=""
RUN_ID=""
WORKSPACE="$DEFAULT_WORKSPACE"
RECIPE_FILTER=""
TOKEN=""
SETUP_DEFAULTS_ONLY=0
GITHUB_TOKEN_FOR_DEFAULTS=""
KEEP_TEMPS=0
AUTOPKG_FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -b|--backend-url)
      BACKEND_URL="${2:?}"
      shift 2
      ;;
    -r|--run-id)
      RUN_ID="${2:?}"
      shift 2
      ;;
    -w|--workspace)
      WORKSPACE="${2:?}"
      shift 2
      ;;
    --recipes)
      RECIPE_FILTER="${2:?}"
      shift 2
      ;;
    -t|--token)
      TOKEN="${2:?}"
      shift 2
      ;;
    --setup-defaults)
      SETUP_DEFAULTS_ONLY=1
      shift
      ;;
    --github-token)
      GITHUB_TOKEN_FOR_DEFAULTS="${2:?}"
      shift 2
      ;;
    --keep-temps)
      KEEP_TEMPS=1
      shift
      ;;
    --autopkg-force)
      AUTOPKG_FORCE=1
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

BACKEND_URL="${BACKEND_URL%/}"

setup_autopkg_defaults() {
  local root="$1"
  echo "Creating directories under $root ..."
  mkdir -p \
    "$root/pkgs" \
    "$root/pkgsinfo" \
    "$root/AutoPkg/Overrides" \
    "$root/AutoPkg/repos" \
    "$root/AutoPkg/Reports" \
    "$root/AutoPkg/Cache" \
    "$HOME/Library/AutoPkg"

  echo "Writing AutoPkg preferences (com.github.autopkg) ..."
  defaults write com.github.autopkg CACHE_DIR "$root/AutoPkg/Cache"
  defaults write com.github.autopkg RECIPE_OVERRIDE_DIRS "$root/AutoPkg/Overrides/"
  defaults write com.github.autopkg RECIPE_REPO_DIR "$root/AutoPkg/repos/"
  defaults write com.github.autopkg FAIL_RECIPES_WITHOUT_TRUST_INFO -bool TRUE
  defaults write com.github.autopkg MUNKI_REPO "$root"
  if [[ -n "$GITHUB_TOKEN_FOR_DEFAULTS" ]]; then
    defaults write com.github.autopkg GITHUB_TOKEN "$GITHUB_TOKEN_FOR_DEFAULTS"
    echo "Set GITHUB_TOKEN in AutoPkg preferences."
  fi
  echo "Defaults applied. Repo root (MUNKI_REPO): $root"
}

# Remove per-run scratch files from the repo root (default). Overrides under
# AutoPkg/Overrides/ are left in place — they are refreshed from the API next run.
cleanup_local_run_temps() {
  emulate -L zsh
  setopt null_glob
  local root="${GITHUB_WORKSPACE:-}"
  [[ -n "$root" && -d "$root" ]] || return 0
  echo "==> Cleaning up temporary run files ..."
  rm -f \
    "$root/metadata_cache_response.json" \
    "$root/metadata_cache.json" \
    "$root/run_config.json" \
    "$root/autopkg_runner.log" \
    "$root/AutoPkg/run_recipe_list.json" \
    "$root/AutoPkg/run_repo_list.txt"
  rm -f "$root/AutoPkg/Reports/"*.plist
}

if [[ "$SETUP_DEFAULTS_ONLY" -eq 1 ]]; then
  setup_autopkg_defaults "$WORKSPACE"
  exit 0
fi

if [[ -z "$BACKEND_URL" || -z "$RUN_ID" ]]; then
  echo "Error: --backend-url and --run-id are required (unless using --setup-defaults)." >&2
  usage >&2
  exit 1
fi

if [[ -n "${AUTOMUNKI_API_TOKEN:-}" && -z "$TOKEN" ]]; then
  TOKEN="$AUTOMUNKI_API_TOKEN"
fi
if [[ -n "$TOKEN" ]]; then
  export AUTOMUNKI_API_TOKEN="$TOKEN"
fi

export GITHUB_WORKSPACE="$WORKSPACE"
export BACKEND_URL
export RUN_ID
cd "$GITHUB_WORKSPACE" || exit 1

if [[ "$KEEP_TEMPS" -eq 0 ]]; then
  trap cleanup_local_run_temps EXIT
fi

API_BASE="${BACKEND_URL}/api/v1/autopkg"

curl_auth() {
  if [[ -n "${TOKEN:-}" ]]; then
    curl -sS -H "Authorization: Bearer ${TOKEN}" "$@"
  else
    curl -sS "$@"
  fi
}

echo "==> Fetching metadata cache ..."
HTTP_CODE=$(curl_auth -o metadata_cache_response.json -w "%{http_code}" "${API_BASE}/metadata-cache")
if [[ "$HTTP_CODE" == "200" ]]; then
  python3 AutoPkg/scripts/load_metadata_cache.py
else
  echo '{}' > metadata_cache.json
  echo "    (no cache or HTTP $HTTP_CODE; using empty cache)"
fi

QUERY=""
if [[ -n "$RECIPE_FILTER" ]]; then
  QUERY="?recipes=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$RECIPE_FILTER")"
fi

echo "==> Fetching run config and writing overrides ..."
curl_auth -sf "${API_BASE}/runs/config${QUERY}" -o run_config.json
python3 AutoPkg/scripts/write_overrides.py

echo "==> Adding/updating recipe repos ..."
xargs -L1 autopkg repo-add < AutoPkg/run_repo_list.txt
autopkg repo-update all

if [[ "$AUTOPKG_FORCE" -eq 1 ]]; then
  echo "==> Running AutoPkg with --force (sequential; bypasses cloud-autopkg-runner) ..."
  AUTOPKG_BIN="$(command -v autopkg 2>/dev/null || true)"
  if [[ -z "$AUTOPKG_BIN" && -x /usr/local/bin/autopkg ]]; then
    AUTOPKG_BIN=/usr/local/bin/autopkg
  fi
  if [[ -z "$AUTOPKG_BIN" && -x /opt/homebrew/bin/autopkg ]]; then
    AUTOPKG_BIN=/opt/homebrew/bin/autopkg
  fi
  if [[ -z "$AUTOPKG_BIN" ]]; then
    echo "Error: autopkg not found. Install AutoPkg and ensure it is on PATH (or at /usr/local/bin or /opt/homebrew/bin)." >&2
    exit 1
  fi
  export AUTOPKG_BIN
  mkdir -p "$GITHUB_WORKSPACE/AutoPkg/Reports"
  python3 <<'PY'
import json
import os
import subprocess
import sys

ws = os.environ["GITHUB_WORKSPACE"]
ap = os.environ["AUTOPKG_BIN"]
path = os.path.join(ws, "AutoPkg", "run_recipe_list.json")
with open(path) as f:
    recipes = json.load(f)
for recipe in recipes:
    # Basename must match DB identifier stem (local.munki.<NAME>) for report_results.py
    if recipe.endswith(".munki.recipe"):
        product = recipe[: -len(".munki.recipe")]
        report_name = f"local.munki.{product}.plist"
    else:
        report_name = recipe.replace("/", "_") + ".plist"
    report = os.path.join(ws, "AutoPkg", "Reports", report_name)
    cmd = [ap, "run", recipe, "-v", "--force", f"--report-plist={report}"]
    print("   ", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, cwd=ws)
    if r.returncode != 0:
        sys.exit(r.returncode)
sys.exit(0)
PY
else
  echo "==> Running cloud-autopkg-runner ..."
  uvx 'cloud-autopkg-runner' -v \
    --recipe-list AutoPkg/run_recipe_list.json \
    --cache-file metadata_cache.json \
    --cache-plugin json \
    --log-file autopkg_runner.log \
    --report-dir AutoPkg/Reports/
fi

echo "==> Saving metadata cache and reporting results ..."
export API_BASE_URL="$BACKEND_URL"
python3 AutoPkg/scripts/save_metadata_cache.py

REPORT_DIR="AutoPkg/Reports"
PKGSINFO_DIR="${GITHUB_WORKSPACE}/pkgsinfo"
mkdir -p "$PKGSINFO_DIR"

report_plists=("$REPORT_DIR"/*.plist(N))
if [[ ! -d "$REPORT_DIR" ]] || [[ ${#report_plists[@]} -eq 0 ]]; then
  echo "No report plists; marking run complete."
  curl_auth -sf -X POST "${API_BASE_URL}/api/v1/autopkg/runs/${RUN_ID}/complete" \
    -H "Content-Type: application/json" \
    -d '{}'
  echo "Done."
  exit 0
fi

export RUN_ID
for report in "$REPORT_DIR"/*.plist(N); do
  echo "    Processing ${report:t}"
  REPORT_FILE="$report" PKGSINFO_DIR="$PKGSINFO_DIR" python3 AutoPkg/scripts/report_results.py
done

curl_auth -sf -X POST "${API_BASE_URL}/api/v1/autopkg/runs/${RUN_ID}/complete" \
  -H "Content-Type: application/json" \
  -d '{}'

echo "Done."
