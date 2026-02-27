from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from automunki.api.routes.audit import router as audit_router
from automunki.api.routes.auth import router as auth_router
from automunki.api.routes.auth import users_router
from automunki.api.routes.autopkg import router as autopkg_router
from automunki.api.routes.catalogs import router as catalogs_router
from automunki.api.routes.manifests import router as manifests_router
from automunki.api.routes.pkginfo import router as pkginfo_router
from automunki.api.routes.reports import router as reports_router
from automunki.api.routes.sync import router as sync_router
from automunki.core.config import settings

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer()
        if settings.debug
        else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(0),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("automunki_starting", version="0.1.0")
    yield
    logger.info("automunki_shutting_down")


app = FastAPI(
    title="AutoMunki API",
    description="Munki and AutoPkg web management platform",
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app, endpoint="/metrics")

from automunki.core.middleware import RequestIDMiddleware

app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_prefix = "/api/v1"
app.include_router(auth_router, prefix=api_prefix)
app.include_router(users_router, prefix=api_prefix)
app.include_router(pkginfo_router, prefix=api_prefix)
app.include_router(catalogs_router, prefix=api_prefix)
app.include_router(manifests_router, prefix=api_prefix)
app.include_router(autopkg_router, prefix=api_prefix)
app.include_router(sync_router, prefix=api_prefix)
app.include_router(reports_router, prefix=api_prefix)
app.include_router(audit_router, prefix=api_prefix)


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/ready")
async def ready():
    from fastapi.responses import JSONResponse
    from sqlalchemy import text

    from automunki.core.db import engine

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not_ready"})
