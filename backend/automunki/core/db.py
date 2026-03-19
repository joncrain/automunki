from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from automunki.core.config import settings

_is_neon = "neon.tech" in settings.database_url

engine = create_async_engine(
    settings.database_url,
    echo=settings.database_echo,
    pool_size=5 if _is_neon else 20,
    max_overflow=5 if _is_neon else 10,
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={"ssl": "require"} if _is_neon else {},
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session
