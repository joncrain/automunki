from typing import Literal

from pydantic import BaseModel


class AuthConfigResponse(BaseModel):
    """Public settings for the SPA (no auth required)."""

    auth_mode: Literal["disabled", "jwt", "oidc"]
    #: Mirrors ``AUTH_REGISTRATION_OPEN``; ``False`` when ``AUTH_MODE=disabled``.
    registration_open: bool
