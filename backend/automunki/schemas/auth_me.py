from pydantic import BaseModel

from automunki.schemas.user import UserRead


class MeResponse(BaseModel):
    user: UserRead
    permissions: dict[str, str]
    auth_mode: str
