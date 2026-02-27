from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.api.deps import get_session
from automunki.core.security import current_optional_user
from automunki.models.munki import SyncJob, SyncStatus
from automunki.models.user import User
from automunki.services.audit import create_audit_entry
from automunki.services.s3 import dispatch_repo_sync_workflow

router = APIRouter(prefix="/sync", tags=["sync"])


@router.post("/compile")
async def trigger_sync(
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_optional_user),
):
    job = SyncJob(
        status=SyncStatus.pending,
        triggered_by=user.email if user else "anonymous",
        trigger_type="manual",
    )
    session.add(job)
    await session.flush()

    result = await dispatch_repo_sync_workflow(sync_job_id=str(job.id))
    if "error" in result:
        job.status = SyncStatus.failed
        job.error_message = result["error"]
    else:
        job.status = SyncStatus.running

    await create_audit_entry(
        session,
        action="trigger_sync",
        entity_type="sync_job",
        entity_id=str(job.id),
        user_id=user.id if user else None,
        user_email=user.email if user else None,
    )

    await session.commit()
    return {"job_id": str(job.id), "status": job.status.value}


@router.get("/status")
async def sync_status(session: AsyncSession = Depends(get_session)):
    result = await session.execute(
        select(SyncJob).order_by(SyncJob.created_at.desc()).limit(1)
    )
    job = result.scalar_one_or_none()
    if not job:
        return {"status": "no_syncs"}
    return {
        "job_id": str(job.id),
        "status": job.status.value,
        "triggered_by": job.triggered_by,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "files_synced": job.files_synced,
        "error_message": job.error_message,
    }


@router.get("/history")
async def sync_history(
    session: AsyncSession = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    count = (
        await session.execute(select(func.count()).select_from(SyncJob))
    ).scalar() or 0

    result = await session.execute(
        select(SyncJob)
        .order_by(SyncJob.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    jobs = result.scalars().all()

    return {
        "items": [
            {
                "id": str(j.id),
                "status": j.status.value,
                "triggered_by": j.triggered_by,
                "trigger_type": j.trigger_type,
                "files_synced": j.files_synced,
                "started_at": j.started_at,
                "completed_at": j.completed_at,
                "error_message": j.error_message,
                "created_at": j.created_at,
            }
            for j in jobs
        ],
        "total": count,
        "page": page,
        "page_size": page_size,
    }
