import uuid
from datetime import datetime

from fastapi_users import schemas
from pydantic import Field, computed_field


class UserRead(schemas.BaseUser[uuid.UUID]):
    display_name: str | None = None
    role: str = "viewer"
    updated_at: datetime | None = None
    avatar_filename: str | None = Field(default=None, exclude=True)

    @computed_field
    @property
    def has_avatar(self) -> bool:
        return self.avatar_filename is not None


class UserCreate(schemas.BaseUserCreate):
    display_name: str | None = None


class UserUpdate(schemas.BaseUserUpdate):
    display_name: str | None = None
