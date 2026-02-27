from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class AuditLogRead(BaseModel):
    id: UUID
    user_id: UUID | None = None
    user_email: str | None = None
    action: str
    entity_type: str
    entity_id: str
    entity_name: str | None = None
    before_snapshot: dict | None = None
    after_snapshot: dict | None = None
    changes: dict | None = None
    ip_address: str | None = None
    notes: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
