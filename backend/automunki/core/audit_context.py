"""Request-scoped audit user (set by RBAC middleware)."""

from __future__ import annotations

import uuid
from contextvars import ContextVar

audit_user_id_ctx: ContextVar[uuid.UUID | None] = ContextVar("audit_user_id", default=None)
audit_user_email_ctx: ContextVar[str | None] = ContextVar("audit_user_email", default=None)
