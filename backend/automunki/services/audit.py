import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from automunki.models.audit import AuditLog


async def create_audit_entry(
    session: AsyncSession,
    *,
    action: str,
    entity_type: str,
    entity_id: str,
    entity_name: str | None = None,
    user_id: uuid.UUID | None = None,
    user_email: str | None = None,
    before_snapshot: dict | None = None,
    after_snapshot: dict | None = None,
    changes: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    notes: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        entity_name=entity_name,
        user_id=user_id,
        user_email=user_email,
        before_snapshot=before_snapshot,
        after_snapshot=after_snapshot,
        changes=changes,
        ip_address=ip_address,
        user_agent=user_agent,
        notes=notes,
    )
    session.add(entry)
    await session.flush()
    return entry
