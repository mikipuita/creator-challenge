"""FastAPI entry point for the DomainVitals backend."""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers.report import router as report_router
from app.routers.results import router as results_router
from app.routers.scan import router as scan_router

settings = get_settings()


def _get_allowed_origins(raw_origins: str) -> list[str]:
    """Parse a comma-separated allowed origins string into a clean list."""

    origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
    return origins or ["http://localhost:3000"]


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="AI-powered attack surface monitoring for small businesses.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_get_allowed_origins(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api")
app.include_router(results_router, prefix="/api")
app.include_router(report_router, prefix="/api")


@app.get("/api/health")
async def health_check() -> dict:
    """Simple health endpoint for local development and container probes."""

    return {"status": "ok", "app": settings.app_name, "port": settings.port}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", settings.port)),
        reload=False,
    )
