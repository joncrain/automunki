#!/usr/bin/env zsh
# Poll AutoMunki for pending local AutoPkg runs and execute them automatically.
# Requires server LOCAL_RUNNER_TOKEN (see docs/local-autopkg-runner.md).
#
# Example (launchd):
#   export AUTOMUNKI_BACKEND_URL=https://munki.example.com
#   export LOCAL_RUNNER_TOKEN=$(security find-generic-password -s automunki-local-runner -w)
#   /path/to/automunki/AutoPkg/scripts/poll_local_autopkg.sh

set -euo pipefail

SCRIPT_PATH="${0:A}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
RUN_SCRIPT="${SCRIPT_DIR}/run_local_autopkg.sh"
DEFAULT_WORKSPACE="$(cd "$SCRIPT_DIR/../.." && pwd)"

usage() {
  cat <<'EOF'
Usage: poll_local_autopkg.sh --backend-url URL [options]

Required:
  -b, --backend-url URL   API origin (no /api/v1). Same as run_local_autopkg.sh.

Auth (one required):
  -t, --token TOKEN       LOCAL_RUNNER_TOKEN (or long-lived JWT with AutoPkg access)
      Or set LOCAL_RUNNER_TOKEN or AUTOMUNKI_API_TOKEN in the environment.

Optional:
  -w, --workspace PATH    automunki repo root (default: parent of AutoPkg/scripts)
  -i, --interval SEC      Seconds to wait when no run is pending (default: 30)
  -h, --help

Environment:
  AUTOMUNKI_BACKEND_URL   Default for --backend-url
  LOCAL_RUNNER_TOKEN      Preferred bearer for claim + runner (matches server)
  AUTOMUNKI_API_TOKEN     Fallback bearer (same as run_local_autopkg.sh)

EOF
}

BACKEND_URL="${AUTOMUNKI_BACKEND_URL:-}"
TOKEN="${LOCAL_RUNNER_TOKEN:-${AUTOMUNKI_API_TOKEN:-}}"
WORKSPACE="$DEFAULT_WORKSPACE"
POLL_INTERVAL=30

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
    -t|--token)
      TOKEN="${2:?}"
      shift 2
      ;;
    -w|--workspace)
      WORKSPACE="${2:?}"
      shift 2
      ;;
    -i|--interval)
      POLL_INTERVAL="${2:?}"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

BACKEND_URL="${BACKEND_URL%/}"

if [[ -z "$BACKEND_URL" ]]; then
  echo "Error: --backend-url or AUTOMUNKI_BACKEND_URL is required." >&2
  usage >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then
  echo "Error: set LOCAL_RUNNER_TOKEN, AUTOMUNKI_API_TOKEN, or pass --token." >&2
  exit 1
fi

CLAIM_URL="${BACKEND_URL}/api/v1/autopkg/runs/claim-next-local"

echo "Polling ${CLAIM_URL} every ${POLL_INTERVAL}s (workspace: ${WORKSPACE})"

while true; do
  HTTP_CODE=$(curl -sS -o /tmp/automunki-claim.json -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    "$CLAIM_URL")

  if [[ "$HTTP_CODE" == "204" ]]; then
    sleep "$POLL_INTERVAL"
    continue
  fi

  if [[ "$HTTP_CODE" != "200" ]]; then
    echo "claim-next-local failed: HTTP ${HTTP_CODE}" >&2
    cat /tmp/automunki-claim.json >&2 || true
    sleep 60
    continue
  fi

  RUN_ID=$(python3 -c 'import json,sys; print(json.load(open("/tmp/automunki-claim.json"))["id"])')
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Claimed run ${RUN_ID}; starting AutoPkg ..."

  set +e
  "$RUN_SCRIPT" --backend-url "$BACKEND_URL" --run-id "$RUN_ID" --workspace "$WORKSPACE" --token "$TOKEN"
  RC=$?
  set -e

  if [[ "$RC" -ne 0 ]]; then
    echo "run_local_autopkg.sh exited ${RC}; pausing 60s before next poll." >&2
    sleep 60
  fi
done
