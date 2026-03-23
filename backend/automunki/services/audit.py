import uuid
from datetime import date, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from automunki.core.audit_context import audit_user_email_ctx, audit_user_id_ctx
from automunki.models.audit import AuditLog


def _make_json_safe(obj: object) -> object:
    """Recursively convert a value so it is safe for ``json.dumps``."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): _make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_json_safe(v) for v in obj]
    return str(obj)


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
    if user_id is None:
        user_id = audit_user_id_ctx.get()
    if user_email is None:
        user_email = audit_user_email_ctx.get()
    entry = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        entity_name=entity_name,
        user_id=user_id,
        user_email=user_email,
        before_snapshot=_make_json_safe(before_snapshot) if before_snapshot else None,
        after_snapshot=_make_json_safe(after_snapshot) if after_snapshot else None,
        changes=_make_json_safe(changes) if changes else None,
        ip_address=ip_address,
        user_agent=user_agent,
        notes=notes,
    )
    session.add(entry)
    await session.flush()
    return entry
