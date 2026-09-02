import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    if settings.uses_default_jwt_secret:
        logger.warning("JWT_SECRET_KEY is the built-in development default. Set a random secret before any shared deployment.")
    app = FastAPI(title=settings.app_name, version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.frontend_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.include_router(api_router, prefix=settings.api_v1_prefix)
    return app


app = create_app()

