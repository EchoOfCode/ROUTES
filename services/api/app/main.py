import logging

from fastapi import APIRouter, FastAPI
from sqlalchemy import text

from app.api import assessments, auth, overview, projects
from app.core.config import get_settings
from app.core.csrf import CsrfMiddleware
from app.core.db import get_engine
from app.core.errors import install_error_handlers
from app.core.redis import get_redis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ROUTES API",
        version="0.1.0",
        docs_url="/api/docs" if settings.environment != "production" else None,
        openapi_url="/api/openapi.json" if settings.environment != "production" else None,
        redoc_url=None,
    )
    install_error_handlers(app)
    app.add_middleware(CsrfMiddleware)

    v1 = APIRouter(prefix="/api/v1")
    v1.include_router(auth.router)
    v1.include_router(projects.router)
    v1.include_router(assessments.router)
    v1.include_router(overview.router)
    app.include_router(v1)

    @app.get("/api/health", tags=["health"])
    def health() -> dict:
        status = {"api": "ok", "database": "ok", "redis": "ok"}
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            status["database"] = "unavailable"
        try:
            get_redis().ping()
        except Exception:
            status["redis"] = "unavailable"
        return status

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response

    return app


app = create_app()
