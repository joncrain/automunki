"""Download the metadata cache from the AutoMunki API into metadata_cache.json.

Paths inside the cache may reference the last runner's disk (e.g. GitHub Actions
``/Users/runner/work/<owner>/<repo>/...``). When ``GITHUB_WORKSPACE`` is set
(Actions or local clone), those prefixes are rewritten so ``cloud-autopkg-runner``
does not try to write under ``/Users/runner`` on a developer Mac.
"""

from __future__ import annotations

import json
import os
import re

# Default checkout path on GitHub-hosted macOS runners (see GITHUB_WORKSPACE)
_RUNNER_REPO_ROOT = re.compile(r"^/Users/runner/work/[^/]+/[^/]+")

response_file = "metadata_cache_response.json"
output_file = "metadata_cache.json"


def _rewrite_runner_paths(obj: object, workspace: str) -> object:
    """Replace GitHub Actions workspace prefix with the current GITHUB_WORKSPACE."""

    def fix_str(s: str) -> str:
        if _RUNNER_REPO_ROOT.match(s):
            return _RUNNER_REPO_ROOT.sub(workspace, s, count=1)
        return s

    if isinstance(obj, dict):
        return {k: _rewrite_runner_paths(v, workspace) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_rewrite_runner_paths(v, workspace) for v in obj]
    if isinstance(obj, str):
        return fix_str(obj)
    return obj


if not os.path.exists(response_file):
    print("No API response file found, starting with empty cache")
    with open(output_file, "w") as f:
        json.dump({}, f)
    raise SystemExit(0)

with open(response_file) as f:
    resp = json.load(f)

cache = resp.get("cache_data", {})
ws = os.environ.get("GITHUB_WORKSPACE", "").strip()
if ws:
    before = json.dumps(cache)
    cache = _rewrite_runner_paths(cache, ws)
    if json.dumps(cache) != before:
        print(f"Rewrote GitHub Actions paths in metadata cache → GITHUB_WORKSPACE={ws!r}")

with open(output_file, "w") as f:
    json.dump(cache, f, indent=4)
print(f"Loaded metadata cache with {len(cache)} entries")
