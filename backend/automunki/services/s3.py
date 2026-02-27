"""S3 upload and sync coordination service."""

import structlog

from automunki.core.config import settings

logger = structlog.get_logger()


async def dispatch_repo_sync_workflow(*, sync_job_id: str) -> dict:
    """Trigger the repo-sync GitHub Actions workflow."""
    if not settings.github_token or not settings.github_repo:
        return {"error": "GitHub token or repo not configured"}

    from httpx import AsyncClient

    url = f"https://api.github.com/repos/{settings.github_repo}/actions/workflows/repo-sync.yml/dispatches"
    headers = {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    async with AsyncClient() as client:
        response = await client.post(
            url,
            headers=headers,
            json={
                "ref": "main",
                "inputs": {"sync_job_id": sync_job_id},
            },
        )

    if response.status_code == 204:
        logger.info("repo_sync_dispatched", sync_job_id=sync_job_id)
        return {"status": "dispatched"}

    logger.error(
        "repo_sync_dispatch_failed",
        status_code=response.status_code,
        body=response.text,
    )
    return {"error": f"Dispatch failed: {response.status_code}"}
