from collections.abc import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from automunki.core.db import get_async_session
from automunki.core.security import current_active_user, current_optional_user


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_async_session():
        yield session


SessionDep = Depends(get_session)
CurrentUser = Depends(current_active_user)
OptionalUser = Depends(current_optional_user)
