import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import Settings, get_settings
from app.services.store import AnalysisStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = resolved
        app.state.store = AnalysisStore(resolved.database_path)
        yield

    app = FastAPI(
        title=resolved.app_name,
        version=resolved.version,
        description="Email threat detection, origin tracing, and forensic analysis.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.allowed_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)

    @app.get("/")
    def root() -> dict[str, str]:
        return {
            "name": resolved.app_name,
            "version": resolved.version,
            "docs": "/docs",
            "health": "/api/health",
        }

    return app


app = create_app()
