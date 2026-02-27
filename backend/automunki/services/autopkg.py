"""AutoPkg integration service - GitHub Actions dispatch and result ingestion."""

from __future__ import annotations

import re

import structlog
from httpx import AsyncClient

from automunki.core.config import settings

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

    url = f"{GITHUB_API}/repos/{settings.github_repo}/actions/workflows/autopkg.yml/dispatches"

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
                    }
                )
            page += 1

    return repos


async def discover_recipes_in_repo(repo_full_name: str) -> list[dict]:
    """
    Search a GitHub repo for .munki.recipe and .munki.recipe.yaml files
    using the Git tree API (recursive).
    """
    recipes: list[dict] = []
    async with AsyncClient(timeout=60) as client:
        # Get the default branch SHA
        resp = await client.get(
            f"{GITHUB_API}/repos/{repo_full_name}/git/refs/heads/main",
            headers=_github_headers(),
        )
        if resp.status_code == 404:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo_full_name}/git/refs/heads/master",
                headers=_github_headers(),
            )
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
                "url": f"https://github.com/{repo_full_name}/blob/main/{path}",
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
