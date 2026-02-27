from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.api.deps import get_session
from automunki.models.audit import AuditLog
from automunki.schemas.audit import AuditLogRead
from automunki.schemas.common import PaginatedResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=PaginatedResponse)
async def list_audit_logs(
    session: AsyncSession = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    entity_type: str | None = None,
    action: str | None = None,
    user_email: str | None = None,
):
    query = select(AuditLog)

    if entity_type:
        query = query.where(AuditLog.entity_type == entity_type)
    if action:
        query = query.where(AuditLog.action == action)
    if user_email:
        query = query.where(AuditLog.user_email == user_email)

    count = (
        await session.execute(select(func.count()).select_from(query.subquery()))
    ).scalar() or 0

    result = await session.execute(
        query.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = [AuditLogRead.model_validate(a) for a in result.scalars().all()]

    return PaginatedResponse(
        items=items,
        total=count,
        page=page,
        page_size=page_size,
        total_pages=(count + page_size - 1) // page_size,
    )


@router.get("/{entity_type}/{entity_id}", response_model=list[AuditLogRead])
async def get_entity_audit_trail(
    entity_type: str,
    entity_id: str,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(AuditLog)
        .where(AuditLog.entity_type == entity_type, AuditLog.entity_id == entity_id)
        .order_by(AuditLog.created_at.desc())
    )
    return [AuditLogRead.model_validate(a) for a in result.scalars().all()]
