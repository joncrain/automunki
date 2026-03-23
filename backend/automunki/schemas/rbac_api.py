import uuid
from typing import Literal

from pydantic import BaseModel, Field


class RolePermissionRow(BaseModel):
    page_key: str
    access_level: Literal["none", "read", "write"]


class RoleRead(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    is_system: bool
    permissions: list[RolePermissionRow]

    model_config = {"from_attributes": False}


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None


class RolePermissionsUpdate(BaseModel):
    permissions: list[RolePermissionRow]


class UserRolesRead(BaseModel):
    user_id: uuid.UUID
    email: str
    is_superuser: bool
    role_ids: list[uuid.UUID]


class UserRolesUpdate(BaseModel):
    role_ids: list[uuid.UUID]
