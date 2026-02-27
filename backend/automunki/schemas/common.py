from uuid import UUID

from pydantic import BaseModel


class PaginationParams(BaseModel):
    page: int = 1
    page_size: int = 50
    sort_by: str | None = None
    sort_order: str = "asc"


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    total_pages: int


class MessageResponse(BaseModel):
    message: str
    detail: str | None = None


class IDResponse(BaseModel):
    id: UUID
