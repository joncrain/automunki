"""
Trust verification engine for AutoPkg recipes.

Implements Python-native trust verification and update logic,
operating entirely via GitHub API (no local filesystem or autopkg CLI needed).

Trust info structure:
{
    "parent_recipes": {
        "<identifier>": {
            "sha256_hash": "<hex digest>",
            "github_repo": "<owner/repo>",
            "github_path": "<path/to/file>"
        }
    },
    "non_core_processors": {
        "<ProcessorName>": {
            "sha256_hash": "<hex digest>",
            "github_repo": "<owner/repo>",
            "github_path": "<path/to/file>"
        }
    }
}

Verification compares only sha256_hash values. The github_repo and
github_path fields are stored so that verification can fetch files
directly without needing to re-resolve identifiers.
"""

from __future__ import annotations

import base64
import hashlib
import plistlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import quote

import structlog
import yaml
from httpx import AsyncClient

from automunki.core.config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()

GITHUB_API = "https://api.github.com"

CORE_PROCESSORS = frozenset(
    {
        "Copier",
        "CURLDownloader",
        "CURLTextSearcher",
        "CodeSignatureVerifier",
        "DmgCreator",
        "DmgMounter",
        "Downloader",
        "EndOfCheckPhase",
        "FileFinder",
        "FileMover",
        "FlatPkgPacker",
        "FlatPkgUnpacker",
        "GitHubReleasesInfoProvider",
        "Installer",
        "InstallFromDMG",
        "MunkiCatalogBuilder",
        "MunkiImporter",
        "MunkiInstallsItemsCreator",
        "MunkiPkginfoMerger",
        "MunkiSetDefaultCatalog",
        "PackageRequired",
        "PathDeleter",
        "PkgCopier",
        "PkgCreator",
        "PkgExtractor",
        "PkgInfoCreator",
        "PkgPayloadUnpacker",
        "PlistEditor",
        "PlistReader",
        "SparkleUpdateInfoProvider",
        "StopProcessingIf",
        "Symlinker",
        "Unarchiver",
        "URLDownloader",
        "URLGetter",
        "URLTextSearcher",
        "Versioner",
    }
)


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


class GitHubRateLimitError(Exception):
    """Raised when the GitHub API rate limit is exhausted."""

    def __init__(self, reset_at: int | None = None):
        self.reset_at = reset_at
        super().__init__(
            f"GitHub API rate limit exceeded (resets at {reset_at})" if reset_at else "GitHub API rate limit exceeded"
        )


@dataclass
class TrustVerificationResult:
    status: str  # "verified" | "failed" | "error"
    diff: dict = field(default_factory=dict)
    error: str | None = None


# ── Low-level GitHub helpers ──────────────────────────────────────────────


async def _fetch_file_bytes(repo: str, path: str, *, raise_on_rate_limit: bool = True) -> bytes | None:
    """Fetch raw file content from GitHub Contents API."""
    try:
        async with AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo}/contents/{path}",
                headers=_github_headers(),
            )
    except Exception as exc:
        logger.debug("github_fetch_error", repo=repo, path=path, error=str(exc))
        return None

    if resp.status_code == 403:
        reset_at = resp.headers.get("x-ratelimit-reset")
        remaining = resp.headers.get("x-ratelimit-remaining")
        if remaining == "0" or "rate limit" in resp.text.lower():
            logger.warning(
                "github_rate_limit_hit",
                repo=repo,
                path=path,
                reset_at=reset_at,
            )
            if raise_on_rate_limit:
                raise GitHubRateLimitError(reset_at=int(reset_at) if reset_at else None)
            return None
    if resp.status_code != 200:
        logger.debug(
            "github_fetch_failed",
            repo=repo,
            path=path,
            status=resp.status_code,
        )
        return None
    data = resp.json()
    if data.get("encoding") == "base64":
        return base64.b64decode(data["content"])
    return None


async def _sha256_of_file(repo: str, path: str) -> str | None:
    """Fetch a file from GitHub and compute its SHA256 hex digest."""
    content = await _fetch_file_bytes(repo, path)
    if content is None:
        return None
    return hashlib.sha256(content).hexdigest()


async def _parse_recipe(repo: str, path: str) -> dict | None:
    """Fetch and parse a recipe plist or yaml file from GitHub."""
    content = await _fetch_file_bytes(repo, path)
    if content is None:
        return None
    if path.endswith(".yaml"):
        try:
            return yaml.safe_load(content)
        except Exception:
            logger.exception("yaml_parse_error", repo=repo, path=path)
            return None
    try:
        return plistlib.loads(content)
    except Exception:
        logger.exception("plist_parse_error", repo=repo, path=path)
        return None


async def _repo_default_branch(repo: str) -> str | None:
    """Return the default branch name for a repo, or None if not found."""
    async with AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{GITHUB_API}/repos/{repo}",
            headers=_github_headers(),
        )
        if resp.status_code == 403:
            raise GitHubRateLimitError()
        if resp.status_code == 200:
            return resp.json().get("default_branch", "main")
    return None


async def _repo_tree(repo: str, branch: str) -> list[dict] | None:
    """Fetch the full recursive file tree for a repo branch."""
    async with AsyncClient(timeout=30) as client:
        ref_resp = await client.get(
            f"{GITHUB_API}/repos/{repo}/git/refs/heads/{branch}",
            headers=_github_headers(),
        )
        if ref_resp.status_code == 403:
            raise GitHubRateLimitError()
        if ref_resp.status_code != 200:
            return None
        sha = ref_resp.json()["object"]["sha"]
        tree_resp = await client.get(
            f"{GITHUB_API}/repos/{repo}/git/trees/{sha}",
            headers=_github_headers(),
            params={"recursive": "1"},
        )
        if tree_resp.status_code == 403:
            raise GitHubRateLimitError()
        if tree_resp.status_code != 200:
            return None
        return tree_resp.json().get("tree", [])


# ── Local DB cache lookup ─────────────────────────────────────────────────


async def build_location_cache(session: AsyncSession) -> dict[str, tuple[str, str]]:
    """
    Build a mapping of identifier_guess -> (repo_full_name, path) from
    the locally cached github_recipe / github_recipe_repo tables.

    This avoids hitting the GitHub API for identifier resolution when
    the recipe has already been synced to the local cache.
    """
    from sqlalchemy import select

    from automunki.models.autopkg import GitHubRecipe, GitHubRecipeRepo

    result = await session.execute(
        select(
            GitHubRecipe.identifier_guess,
            GitHubRecipe.path,
            GitHubRecipeRepo.full_name,
        ).join(GitHubRecipeRepo, GitHubRecipe.repo_id == GitHubRecipeRepo.id)
    )
    cache: dict[str, tuple[str, str]] = {}
    for row in result.all():
        cache[row.identifier_guess] = (row.full_name, row.path)
    return cache


# ── Identifier → repo/path resolution ────────────────────────────────────


def _parse_identifier(identifier: str) -> tuple[str, str, str] | None:
    """
    Parse an autopkg identifier into (repo_hint, recipe_type, recipe_name).

    Examples:
        com.github.autopkg.wardsparadox.munki.Ghostty
          -> ("wardsparadox", "munki", "Ghostty")
        com.github.swy.download.BraveUniversal
          -> ("swy", "download", "BraveUniversal")
    """
    m = re.match(r"com\.github\.(?:[^.]+)\.([^.]+)\.([^.]+)\.(.+)$", identifier)
    if m:
        return m.group(1), m.group(2), m.group(3)

    m2 = re.match(r"com\.github\.([^.]+)\.([^.]+)\.(.+)$", identifier)
    if m2:
        return m2.group(1), m2.group(2), m2.group(3)

    return None


def _candidate_repos(identifier: str) -> list[str]:
    """
    Return a list of candidate GitHub repo full_names for an identifier.
    Deduplicates while preserving order.
    """
    m4 = re.match(r"com\.github\.([^.]+)\.([^.]+)\.", identifier)
    if not m4:
        return ["autopkg/recipes"]
    org_or_user = m4.group(1)
    repo_hint = m4.group(2)
    candidates = [
        f"autopkg/{repo_hint}-recipes",
        f"autopkg/{org_or_user}-recipes",
        f"{org_or_user}/{repo_hint}-recipes",
        "autopkg/recipes",
    ]
    return list(dict.fromkeys(candidates))


def _candidate_paths(recipe_name: str, recipe_type: str) -> list[str]:
    """
    Return candidate file paths for a recipe based on naming conventions.
    Tries the most common patterns first.
    """
    base = f"{recipe_name}.{recipe_type}.recipe"
    return [
        f"{recipe_name}/{base}.yaml",
        f"{recipe_name}/{base}",
        f"{recipe_name}/{base}.plist",
        f"{base}.yaml",
        f"{base}",
        f"{base}.plist",
    ]


async def _resolve_recipe(
    identifier: str,
    location_cache: dict[str, tuple[str, str]] | None = None,
) -> tuple[str, str] | None:
    """
    Resolve an autopkg recipe identifier to (repo_full_name, path).

    Resolution order:
    1. Local DB cache (0 API calls)
    2. Predictive path matching on candidate repos
    3. Full tree scan (last resort)
    """
    if location_cache and identifier in location_cache:
        repo, path = location_cache[identifier]
        logger.info(
            "recipe_resolved_from_cache",
            identifier=identifier,
            repo=repo,
            path=path,
        )
        return repo, path

    parsed = _parse_identifier(identifier)
    if not parsed:
        logger.warning("cannot_parse_identifier", identifier=identifier)
        return None

    repo_hint, recipe_type, recipe_name = parsed
    repos = _candidate_repos(identifier)

    for repo in repos:
        for candidate_path in _candidate_paths(recipe_name, recipe_type):
            content = await _fetch_file_bytes(repo, candidate_path)
            if content is not None:
                try:
                    if candidate_path.endswith(".yaml"):
                        data = yaml.safe_load(content)
                    else:
                        data = plistlib.loads(content)
                    if data and data.get("Identifier") == identifier:
                        logger.info(
                            "recipe_resolved",
                            identifier=identifier,
                            repo=repo,
                            path=candidate_path,
                        )
                        return repo, candidate_path
                except Exception:
                    continue

        try:
            branch = await _repo_default_branch(repo)
        except GitHubRateLimitError:
            raise
        if not branch:
            continue
        tree = await _repo_tree(repo, branch)
        if not tree:
            continue

        recipe_pattern = re.compile(
            rf"{re.escape(recipe_name)}\.{re.escape(recipe_type)}\.recipe"
            r"(\.yaml|\.plist)?$",
            re.IGNORECASE,
        )
        for item in tree:
            if item["type"] != "blob":
                continue
            if recipe_pattern.search(item["path"]):
                data = await _parse_recipe(repo, item["path"])
                if data and data.get("Identifier") == identifier:
                    logger.info(
                        "recipe_resolved_via_tree",
                        identifier=identifier,
                        repo=repo,
                        path=item["path"],
                    )
                    return repo, item["path"]

    logger.warning("recipe_not_resolved", identifier=identifier, repos_tried=repos)
    return None


# ── Non-core processor resolution ────────────────────────────────────────


def _extract_non_core_processors(recipe_data: dict) -> list[str]:
    """Extract non-core processor names from a recipe's Process list."""
    processors = set()
    for step in recipe_data.get("Process", []):
        proc_name = step.get("Processor", "")
        base_name = proc_name.rsplit("/", 1)[-1] if "/" in proc_name else proc_name
        if base_name and base_name not in CORE_PROCESSORS:
            processors.add(proc_name)
    return sorted(processors)


async def _resolve_processor(repo_full_name: str, processor_name: str) -> tuple[str, str] | None:
    """Resolve a processor name to (repo, path)."""
    if "/" in processor_name:
        parts = processor_name.split("/")
        proc_repo = f"autopkg/{parts[0]}"
        proc_class = parts[1]
    else:
        proc_repo = repo_full_name
        proc_class = processor_name

    branch = await _repo_default_branch(proc_repo)
    if not branch:
        return None
    tree = await _repo_tree(proc_repo, branch)
    if not tree:
        return None

    for item in tree:
        if item["type"] != "blob":
            continue
        p = item["path"]
        if p.endswith(f"{proc_class}.py") or p.endswith(f"{proc_class}.recipe"):
            return proc_repo, p

    return None


# ── Trust info computation ────────────────────────────────────────────────


async def compute_trust_info(
    parent_recipe_identifier: str | None,
    existing_trust_info: dict | None = None,
    location_cache: dict[str, tuple[str, str]] | None = None,
) -> dict:
    """
    Compute trust info by walking the parent recipe chain on GitHub.

    Mirrors autopkg's get_trust_info: for each recipe in the chain
    (the direct parent and all its ancestors), hash the file and record
    the identifier, sha256, and location (repo + path) so verification
    can go directly to the right file later.

    If existing_trust_info is provided (e.g. from a legacy override),
    uses the stored paths as hints to resolve locations that can't be
    found by identifier heuristics alone.

    If location_cache is provided (from build_location_cache), uses it
    to resolve identifiers without any GitHub API calls.
    """
    trust_info: dict = {
        "parent_recipes": {},
        "non_core_processors": {},
    }

    if not parent_recipe_identifier:
        return trust_info

    await _walk_recipe_chain(
        parent_recipe_identifier,
        trust_info,
        existing_trust_info=existing_trust_info,
        location_cache=location_cache,
    )
    return trust_info


async def _walk_recipe_chain(
    identifier: str,
    trust_info: dict,
    _visited: set | None = None,
    existing_trust_info: dict | None = None,
    location_cache: dict[str, tuple[str, str]] | None = None,
    _resolved_cache: dict[str, tuple[str, str]] | None = None,
) -> None:
    """
    Recursively walk the recipe chain starting from `identifier`,
    adding each recipe and its non-core processors to trust_info.

    _resolved_cache stores identifiers already resolved during this walk
    to avoid duplicate GitHub API calls within a single chain traversal.
    """
    if _visited is None:
        _visited = set()
    if _resolved_cache is None:
        _resolved_cache = {}
    if identifier in _visited:
        return
    _visited.add(identifier)

    if identifier in _resolved_cache:
        resolved = _resolved_cache[identifier]
    else:
        resolved = await _resolve_recipe(identifier, location_cache=location_cache)

        if not resolved and existing_trust_info:
            old_entry = existing_trust_info.get("parent_recipes", {}).get(identifier, {})
            if old_entry:
                old_repo = old_entry.get("github_repo")
                old_path = old_entry.get("github_path")
                if old_repo and old_path:
                    resolved = (old_repo, old_path)
                else:
                    legacy_path = old_entry.get("path", "")
                    inferred = _infer_github_location(identifier, legacy_path)
                    if inferred[0] and inferred[1]:
                        resolved = inferred

        if resolved:
            _resolved_cache[identifier] = resolved

    if not resolved:
        logger.warning("chain_recipe_not_found", identifier=identifier)
        return

    repo, path = resolved
    sha256 = await _sha256_of_file(repo, path)
    if sha256:
        trust_info["parent_recipes"][identifier] = {
            "sha256_hash": sha256,
            "github_repo": repo,
            "github_path": path,
        }

    recipe_data = await _parse_recipe(repo, path)
    if not recipe_data:
        return

    for proc_name in _extract_non_core_processors(recipe_data):
        if proc_name in trust_info["non_core_processors"]:
            continue
        proc_resolved = await _resolve_processor(repo, proc_name)
        if proc_resolved:
            proc_repo, proc_path = proc_resolved
            proc_sha = await _sha256_of_file(proc_repo, proc_path)
            if proc_sha:
                trust_info["non_core_processors"][proc_name] = {
                    "sha256_hash": proc_sha,
                    "github_repo": proc_repo,
                    "github_path": proc_path,
                }

    chain_parent = recipe_data.get("ParentRecipe")
    if chain_parent:
        await _walk_recipe_chain(
            chain_parent,
            trust_info,
            _visited,
            existing_trust_info=existing_trust_info,
            location_cache=location_cache,
            _resolved_cache=_resolved_cache,
        )


# ── Trust verification ────────────────────────────────────────────────────


async def verify_trust(
    stored_trust_info: dict | None,
    parent_recipe_identifier: str | None,
) -> TrustVerificationResult:
    """
    Verify trust by re-hashing the files at their stored locations.

    If stored trust_info has github_repo/github_path, we fetch directly
    from those locations (fast, reliable). Otherwise we fall back to
    re-resolving from identifiers (slower, less reliable — handles
    legacy entries).
    """
    if not stored_trust_info:
        return TrustVerificationResult(
            status="error",
            error="No trust info stored for this recipe",
        )

    if not parent_recipe_identifier:
        return TrustVerificationResult(
            status="error",
            error="No parent recipe identifier to verify against",
        )

    try:
        current_trust = await _compute_current_hashes(stored_trust_info)
    except GitHubRateLimitError:
        return TrustVerificationResult(
            status="error",
            error="GitHub API rate limit exceeded. Try again later.",
        )
    except Exception as exc:
        logger.exception("trust_verify_error")
        return TrustVerificationResult(
            status="error",
            error=f"Failed to compute current trust info: {exc}",
        )

    parent_diff = _diff_trust_section(
        stored_trust_info.get("parent_recipes", {}),
        current_trust.get("parent_recipes", {}),
    )
    proc_diff = _diff_trust_section(
        stored_trust_info.get("non_core_processors", {}),
        current_trust.get("non_core_processors", {}),
    )

    if not parent_diff and not proc_diff:
        return TrustVerificationResult(status="verified")

    return TrustVerificationResult(
        status="failed",
        diff={
            "parent_recipes": parent_diff,
            "non_core_processors": proc_diff,
        },
    )


async def _compute_current_hashes(stored_trust_info: dict) -> dict:
    """
    Re-hash files using locations from stored trust info.

    For each entry that has github_repo + github_path, fetch directly
    (fast, 1 API call each). For entries without location info (legacy),
    fall back to identifier resolution (expensive, may use many calls).
    """
    current: dict = {"parent_recipes": {}, "non_core_processors": {}}

    for identifier, entry in stored_trust_info.get("parent_recipes", {}).items():
        repo = entry.get("github_repo")
        path = entry.get("github_path")

        if repo and path:
            sha256 = await _sha256_of_file(repo, path)
        else:
            legacy_path = entry.get("path", "")
            repo, path = _infer_github_location(identifier, legacy_path)
            if repo and path:
                sha256 = await _sha256_of_file(repo, path)
            else:
                try:
                    resolved = await _resolve_recipe(identifier)
                except GitHubRateLimitError:
                    raise
                if resolved:
                    repo, path = resolved
                    sha256 = await _sha256_of_file(repo, path)
                else:
                    sha256 = None

        if sha256:
            current["parent_recipes"][identifier] = {"sha256_hash": sha256}
        else:
            logger.warning(
                "verify_parent_not_found",
                identifier=identifier,
                repo=repo,
                path=path,
            )

    for proc_name, entry in stored_trust_info.get("non_core_processors", {}).items():
        repo = entry.get("github_repo")
        path = entry.get("github_path")

        if repo and path:
            sha256 = await _sha256_of_file(repo, path)
        else:
            legacy_path = entry.get("path", "")
            repo, path = _infer_github_location(proc_name, legacy_path)
            if repo and path:
                sha256 = await _sha256_of_file(repo, path)
            else:
                sha256 = None

        if sha256:
            current["non_core_processors"][proc_name] = {"sha256_hash": sha256}
        else:
            logger.warning(
                "verify_processor_not_found",
                proc_name=proc_name,
                repo=repo,
                path=path,
            )

    return current


def _infer_github_location(identifier: str, local_path: str) -> tuple[str | None, str | None]:
    """
    Infer github_repo and github_path from the local filesystem path
    stored by autopkg.

    Example paths:
      ~/Library/AutoPkg/RecipeRepos/com.github.autopkg.recipes/Mozilla/Firefox.munki.recipe
        -> ("autopkg/recipes", "Mozilla/Firefox.munki.recipe")
      ~/Library/AutoPkg/RecipeRepos/com.github.autopkg.swy-recipes/BraveUniversal/BraveUniversal.download.recipe
        -> ("autopkg/swy-recipes", "BraveUniversal/BraveUniversal.download.recipe")
      ~/Library/AutoPkg/RecipeRepos/com.github.autopkg.wardsparadox-recipes/Ghostty/Ghostty.munki.recipe.yaml
        -> ("autopkg/wardsparadox-recipes", "Ghostty/Ghostty.munki.recipe.yaml")

    The directory name pattern is: com.github.<org>.<repo-name>
    which maps to GitHub: <org>/<repo-name>
    """
    if not local_path:
        return None, None

    path_str = local_path.replace("~", "").strip("/")
    marker = "RecipeRepos/"
    idx = path_str.find(marker)
    if idx < 0:
        return None, None

    after = path_str[idx + len(marker) :]
    parts = after.split("/", 1)
    if len(parts) != 2:
        return None, None

    repo_dir = parts[0]
    file_path = parts[1]

    m = re.match(r"com\.github\.([^.]+)\.(.+)", repo_dir)
    if not m:
        return None, None

    org = m.group(1)
    repo_name = m.group(2)
    github_repo = f"{org}/{repo_name}"

    return github_repo, file_path


def _diff_trust_section(old_section: dict, new_section: dict) -> dict:
    """
    Compare stored trust entries against freshly computed hashes.
    Only compares sha256_hash values.
    """
    changes: dict = {}
    all_keys = set(old_section.keys()) | set(new_section.keys())

    for key in sorted(all_keys):
        old_entry = old_section.get(key)
        new_entry = new_section.get(key)

        old_hash = old_entry.get("sha256_hash") if isinstance(old_entry, dict) else None
        new_hash = new_entry.get("sha256_hash") if isinstance(new_entry, dict) else None

        if old_hash and not new_hash:
            changes[key] = {
                "change": "not_found",
                "old_sha256": old_hash,
            }
        elif new_hash and not old_hash:
            changes[key] = {
                "change": "added",
                "new_sha256": new_hash,
            }
        elif old_hash != new_hash:
            changes[key] = {
                "change": "modified",
                "old_sha256": old_hash,
                "new_sha256": new_hash,
            }

    return changes


# ── Resolve Git commit from trust hash diff ───────────────────────────────


def _contents_url(repo: str, path: str) -> str:
    encoded_path = quote(path, safe="/")
    return f"{GITHUB_API}/repos/{repo}/contents/{encoded_path}"


async def _fetch_file_bytes_at_ref(
    client: AsyncClient,
    repo: str,
    path: str,
    ref: str,
    *,
    raise_on_rate_limit: bool = True,
) -> bytes | None:
    """Fetch file at an arbitrary git ref (commit SHA, branch, or tag)."""
    try:
        resp = await client.get(
            _contents_url(repo, path),
            headers=_github_headers(),
            params={"ref": ref},
        )
    except Exception as exc:
        logger.debug("github_fetch_at_ref_error", repo=repo, path=path, ref=ref, error=str(exc))
        return None

    if resp.status_code == 403:
        reset_at = resp.headers.get("x-ratelimit-reset")
        remaining = resp.headers.get("x-ratelimit-remaining")
        if remaining == "0" or "rate limit" in resp.text.lower():
            if raise_on_rate_limit:
                raise GitHubRateLimitError(reset_at=int(reset_at) if reset_at else None)
            return None
    if resp.status_code != 200:
        return None
    data = resp.json()
    if isinstance(data, list):
        return None
    if data.get("encoding") == "base64" and data.get("content"):
        return base64.b64decode(data["content"])
    return None


async def resolve_introducing_commit(
    repo: str,
    path: str,
    new_sha256: str,
    old_sha256: str | None = None,
    *,
    max_commits: int = 40,
) -> str | None:
    """
    Find a commit SHA that explains a trust hash change.

    Walks recent commits touching ``path`` (newest first). Prefer a commit
    whose tree has file hash ``new_sha256`` and whose first parent's version
    of the file hashes to ``old_sha256`` (when ``old_sha256`` is set).
    Otherwise returns the newest commit where the file already matches
    ``new_sha256`` (e.g. ``added`` entries or ambiguous history).

    Returns None if no match within ``max_commits`` or on API failure.
    """
    if not new_sha256:
        return None
    if old_sha256 == "":
        old_sha256 = None

    per_page = min(max(1, max_commits), 100)

    async with AsyncClient(timeout=45) as client:
        list_resp = await client.get(
            f"{GITHUB_API}/repos/{repo}/commits",
            headers=_github_headers(),
            params={"path": path, "per_page": per_page},
        )
        if list_resp.status_code == 403:
            reset_at = list_resp.headers.get("x-ratelimit-reset")
            remaining = list_resp.headers.get("x-ratelimit-remaining")
            if remaining == "0" or "rate limit" in list_resp.text.lower():
                raise GitHubRateLimitError(reset_at=int(reset_at) if reset_at else None)
        if list_resp.status_code != 200:
            logger.warning(
                "github_list_commits_failed",
                repo=repo,
                path=path,
                status=list_resp.status_code,
            )
            return None

        commits = list_resp.json()
        if not isinstance(commits, list):
            return None
        if not commits:
            return None

        hash_cache: dict[str, str | None] = {}

        async def content_sha256_at(ref: str) -> str | None:
            if ref in hash_cache:
                return hash_cache[ref]
            raw = await _fetch_file_bytes_at_ref(client, repo, path, ref)
            if raw is None:
                hash_cache[ref] = None
                return None
            digest = hashlib.sha256(raw).hexdigest()
            hash_cache[ref] = digest
            return digest

        if old_sha256:
            for c in commits:
                cur_sha = c.get("sha")
                if not cur_sha:
                    continue
                h_cur = await content_sha256_at(cur_sha)
                if h_cur != new_sha256:
                    continue
                parents = c.get("parents") or []
                if not parents:
                    return cur_sha
                parent_sha = parents[0].get("sha")
                if not parent_sha:
                    continue
                h_prev = await content_sha256_at(parent_sha)
                if h_prev == old_sha256:
                    return cur_sha

        for c in commits:
            cur_sha = c.get("sha")
            if not cur_sha:
                continue
            h_cur = await content_sha256_at(cur_sha)
            if h_cur == new_sha256:
                return cur_sha

    return None


# ── Public helpers for override creation ──────────────────────────────────


async def fetch_recipe_content(repo_full_name: str, path: str) -> dict | None:
    """Fetch and parse a recipe file from GitHub."""
    return await _parse_recipe(repo_full_name, path)


async def build_override_data(
    recipe_content: dict,
    repo_full_name: str,
    recipe_path: str,
    location_cache: dict[str, tuple[str, str]] | None = None,
) -> dict:
    """
    Given parsed recipe content from a parent .munki.recipe, build the
    override data structure matching autopkg's make-override output:

    - Identifier: local.munki.<NAME>
    - ParentRecipe: the source recipe's Identifier
    - Input: merged from the full recipe chain
    - ParentRecipeTrustInfo: computed from GitHub hashes

    If location_cache is provided, identifier resolution uses the local
    DB cache instead of hitting the GitHub API.
    """
    source_identifier = recipe_content.get("Identifier", "")
    source_input = dict(recipe_content.get("Input", {}))

    recipe_name = source_input.get("NAME", "")
    if not recipe_name:
        recipe_name = recipe_path.rsplit("/", 1)[-1].split(".munki.recipe")[0]
        source_input["NAME"] = recipe_name

    override_identifier = f"local.munki.{recipe_name}"

    if "MUNKI_REPO_SUBDIR" not in source_input:
        source_input["MUNKI_REPO_SUBDIR"] = "apps/%NAME%"

    if "pkginfo" not in source_input:
        source_input["pkginfo"] = {
            "catalogs": ["testing"],
            "name": "%NAME%",
        }

    seed_cache: dict[str, tuple[str, str]] = {}
    if location_cache:
        seed_cache.update(location_cache)
    seed_cache[source_identifier] = (repo_full_name, recipe_path)

    chain_parent = recipe_content.get("ParentRecipe")
    if chain_parent:
        chain_resolved = await _resolve_recipe(chain_parent, location_cache=seed_cache)
        if chain_resolved:
            chain_repo, chain_path = chain_resolved
            seed_cache[chain_parent] = (chain_repo, chain_path)
            chain_content = await _parse_recipe(chain_repo, chain_path)
            if chain_content:
                chain_input = chain_content.get("Input", {})
                merged = dict(chain_input)
                merged.update(source_input)
                source_input = merged

    trust_info = await compute_trust_info(
        parent_recipe_identifier=source_identifier,
        location_cache=seed_cache,
    )

    return {
        "identifier": override_identifier,
        "parent_recipe": source_identifier,
        "input_variables": source_input if source_input else None,
        "trust_info": trust_info,
    }


def _repo_from_identifier(identifier: str) -> str | None:
    """Infer a GitHub repo full_name from a recipe identifier.

    Handles the common ``com.github.autopkg.<user>.<type>.<name>`` convention
    which maps to ``autopkg/<user>-recipes``.
    """
    parts = identifier.split(".")
    if len(parts) >= 5 and parts[:3] == ["com", "github", "autopkg"]:
        return f"autopkg/{parts[3]}-recipes"
    return None


def infer_repos_from_trust_info(trust_info: dict | None) -> list[str]:
    """Extract the set of GitHub repos referenced in trust info.

    Checks each entry for an explicit ``github_repo`` field first, then
    falls back to parsing the recipe identifier key for the standard
    ``com.github.autopkg.<user>`` convention.

    Returns repo full_names like ``["autopkg/wardsparadox-recipes"]``.
    """
    repos: set[str] = set()
    if not trust_info:
        return []
    for section in ("parent_recipes", "non_core_processors"):
        for identifier, entry in trust_info.get(section, {}).items():
            if isinstance(entry, dict) and entry.get("github_repo"):
                repos.add(entry["github_repo"])
            elif repo := _repo_from_identifier(identifier):
                repos.add(repo)
    return sorted(repos)
