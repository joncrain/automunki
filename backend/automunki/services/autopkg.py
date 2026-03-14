"""AutoPkg integration service - GitHub Actions dispatch and result ingestion."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import structlog
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.core.config import settings
from automunki.models.autopkg import GitHubRecipe, GitHubRecipeRepo

logger = structlog.get_logger()

GITHUB_API = "https://api.github.com"


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


async def dispatch_autopkg_workflow(
    *,
    run_id: str,
    recipe_names: list[str] | None = None,
) -> dict:
    """Trigger the AutoPkg GitHub Actions workflow via workflow_dispatch."""
    if not settings.github_token or not settings.github_repo:
        return {"error": "GitHub token or repo not configured"}

    url = f"{GITHUB_API}/repos/{settings.github_repo}/actions/workflows/autopkg_cloud_runner.yml/dispatches"

    inputs: dict[str, str] = {"run_id": run_id, "api_url": settings.cors_origins[0]}
    if recipe_names:
        inputs["recipe"] = ", ".join(recipe_names)

    async with AsyncClient(timeout=30) as client:
        response = await client.post(
            url,
            headers=_github_headers(),
            json={"ref": "main", "inputs": inputs},
        )

    if response.status_code == 204:
        logger.info("autopkg_workflow_dispatched", run_id=run_id)
        return {"status": "dispatched"}

    logger.error(
        "autopkg_workflow_dispatch_failed",
        status_code=response.status_code,
        body=response.text,
    )
    return {
        "error": f"Dispatch failed: {response.status_code}",
        "detail": response.text,
    }


async def discover_autopkg_repos() -> list[dict]:
    """Query the GitHub autopkg org for available recipe repos."""
    repos: list[dict] = []
    page = 1
    async with AsyncClient(timeout=30) as client:
        while True:
            response = await client.get(
                f"{GITHUB_API}/orgs/autopkg/repos",
                headers=_github_headers(),
                params={"per_page": 100, "page": page, "type": "public"},
            )
            if response.status_code != 200:
                logger.warning("discover_repos_failed", status=response.status_code)
                break
            data = response.json()
            if not data:
                break
            for repo in data:
                name = repo["name"]
                if not name.endswith("-recipes"):
                    continue
                repos.append(
                    {
                        "name": name,
                        "full_name": repo["full_name"],
                        "url": repo["clone_url"],
                        "html_url": repo["html_url"],
                        "description": repo.get("description"),
                        "stars": repo.get("stargazers_count", 0),
                        "updated_at": repo.get("updated_at"),
                        "default_branch": repo.get("default_branch", "main"),
                    }
                )
            page += 1

    return repos


async def discover_recipes_in_repo(
    repo_full_name: str, default_branch: str | None = None
) -> list[dict]:
    """
    Search a GitHub repo for .munki.recipe and .munki.recipe.yaml files
    using the Git tree API (recursive).
    """
    recipes: list[dict] = []
    branch_found = default_branch or "main"

    async with AsyncClient(timeout=60) as client:
        if default_branch:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo_full_name}/git/refs/heads/{default_branch}",
                headers=_github_headers(),
            )
        else:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo_full_name}/git/refs/heads/main",
                headers=_github_headers(),
            )
            if resp.status_code == 404:
                resp = await client.get(
                    f"{GITHUB_API}/repos/{repo_full_name}/git/refs/heads/master",
                    headers=_github_headers(),
                )
                if resp.status_code == 200:
                    branch_found = "master"

        if resp.status_code != 200:
            logger.warning(
                "get_ref_failed", repo=repo_full_name, status=resp.status_code
            )
            return recipes

        sha = resp.json()["object"]["sha"]

        tree_resp = await client.get(
            f"{GITHUB_API}/repos/{repo_full_name}/git/trees/{sha}",
            headers=_github_headers(),
            params={"recursive": "1"},
        )
        if tree_resp.status_code != 200:
            logger.warning(
                "get_tree_failed", repo=repo_full_name, status=tree_resp.status_code
            )
            return recipes

        tree = tree_resp.json().get("tree", [])

    munki_pattern = re.compile(r"\.munki\.recipe(\.yaml|\.plist)?$", re.IGNORECASE)

    for item in tree:
        if item["type"] != "blob":
            continue
        path: str = item["path"]
        if not munki_pattern.search(path):
            continue

        filename = path.rsplit("/", 1)[-1]
        recipe_name = filename.split(".munki.recipe")[0]

        identifier_guess = (
            f"com.github.{repo_full_name.replace('/', '.')}.munki.{recipe_name}"
        )

        recipes.append(
            {
                "name": recipe_name,
                "filename": filename,
                "path": path,
                "identifier_guess": identifier_guess,
                "repo_full_name": repo_full_name,
                "url": f"https://github.com/{repo_full_name}/blob/{branch_found}/{path}",
            }
        )

    return recipes


async def search_github_recipes(query: str = "munki recipe") -> list[dict]:
    """
    Use GitHub code search to find .munki.recipe files across the autopkg org.
    Searches both by filename and by path to catch cases like UnityHub.munki.recipe
    when searching for "unity".
    """
    seen_paths: set[str] = set()
    results: list[dict] = []

    async with AsyncClient(timeout=30) as client:
        # Search by filename containing the query AND .munki.recipe extension
        queries = [
            f"{query} filename:.munki.recipe org:autopkg",
            f"path:{query} extension:recipe org:autopkg",
        ]

        for search_q in queries:
            resp = await client.get(
                f"{GITHUB_API}/search/code",
                headers=_github_headers(),
                params={"q": search_q, "per_page": 50},
            )
            if resp.status_code != 200:
                logger.warning(
                    "code_search_failed",
                    query=search_q,
                    status=resp.status_code,
                    body=resp.text,
                )
                continue

            data = resp.json()
            for item in data.get("items", []):
                filename: str = item["name"]
                if ".munki.recipe" not in filename.lower():
                    continue
                unique_key = f"{item['repository']['full_name']}:{item['path']}"
                if unique_key in seen_paths:
                    continue
                seen_paths.add(unique_key)

                recipe_name = filename.split(".munki.recipe")[0]
                repo_full = item["repository"]["full_name"]
                identifier_guess = (
                    f"com.github.{repo_full.replace('/', '.')}.munki.{recipe_name}"
                )
                results.append(
                    {
                        "name": recipe_name,
                        "filename": filename,
                        "path": item["path"],
                        "identifier_guess": identifier_guess,
                        "repo_full_name": repo_full,
                        "repo_name": item["repository"]["name"],
                        "repo_url": item["repository"]["html_url"],
                        "url": item["html_url"],
                    }
                )

    return results


# ── Local cache sync ─────────────────────────────────────────────────────


async def sync_repos_to_cache(session: AsyncSession) -> dict:
    """
    Fetch all autopkg recipe repos from GitHub and upsert into local cache.
    Returns stats about what was synced.
    """
    remote_repos = await discover_autopkg_repos()
    if not remote_repos:
        return {"error": "No repos fetched from GitHub (rate limited?)"}

    remote_by_name = {r["full_name"]: r for r in remote_repos}

    existing = await session.execute(select(GitHubRecipeRepo))
    existing_by_name = {r.full_name: r for r in existing.scalars().all()}

    added = 0
    updated = 0
    removed = 0

    for full_name, data in remote_by_name.items():
        if full_name in existing_by_name:
            repo = existing_by_name[full_name]
            repo.description = data.get("description")
            repo.stars = data.get("stars", 0)
            repo.html_url = data["html_url"]
            repo.clone_url = data.get("url")
            repo.updated_at = data.get("updated_at")
            repo.default_branch = data.get("default_branch", "main")
            updated += 1
        else:
            repo = GitHubRecipeRepo(
                full_name=full_name,
                name=data["name"],
                html_url=data["html_url"],
                clone_url=data.get("url"),
                description=data.get("description"),
                stars=data.get("stars", 0),
                updated_at=data.get("updated_at"),
                default_branch=data.get("default_branch", "main"),
            )
            session.add(repo)
            added += 1

    stale = set(existing_by_name.keys()) - set(remote_by_name.keys())
    for full_name in stale:
        await session.delete(existing_by_name[full_name])
        removed += 1

    await session.commit()
    logger.info("repos_synced", added=added, updated=updated, removed=removed)
    return {
        "added": added,
        "updated": updated,
        "removed": removed,
        "total": len(remote_repos),
    }


async def sync_repo_recipes_to_cache(
    session: AsyncSession, repo: GitHubRecipeRepo
) -> int:
    """
    Fetch all .munki.recipe files from a single GitHub repo and cache them locally.
    Returns the number of recipes cached.
    """
    remote_recipes = await discover_recipes_in_repo(
        repo.full_name, default_branch=repo.default_branch
    )

    await session.execute(delete(GitHubRecipe).where(GitHubRecipe.repo_id == repo.id))

    for r in remote_recipes:
        session.add(
            GitHubRecipe(
                repo_id=repo.id,
                name=r["name"],
                filename=r["filename"],
                path=r["path"],
                identifier_guess=r["identifier_guess"],
                url=r["url"],
            )
        )

    repo.synced_at = datetime.now(timezone.utc)
    await session.commit()
    logger.info("repo_recipes_synced", repo=repo.full_name, count=len(remote_recipes))
    return len(remote_recipes)


async def sync_all_recipes_to_cache(session: AsyncSession) -> dict:
    """Sync recipes for all cached repos. Can be slow for many repos."""
    repos = (await session.execute(select(GitHubRecipeRepo))).scalars().all()
    total = 0
    synced_repos = 0
    errors = 0
    for repo in repos:
        try:
            count = await sync_repo_recipes_to_cache(session, repo)
            total += count
            synced_repos += 1
        except Exception:
            logger.exception("sync_repo_recipes_error", repo=repo.full_name)
            errors += 1
    return {"repos_synced": synced_repos, "total_recipes": total, "errors": errors}
