"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import ingestion_routes, query_routes, sim_routes, soar_routes
from app.correlation import Detector
from app.state import AppState


def create_app(ttl_days: int | None = None) -> FastAPI:
    app = FastAPI(title="Incidentaling SIEM/SOAR Simulator", version=__version__)

    # The thin Next.js frontend runs on a different origin in dev.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    state = AppState(ttl_days=ttl_days)
    app.state.app_state = state
    app.state.detector = Detector(state)
    app.include_router(ingestion_routes.router)
    app.include_router(query_routes.router)
    app.include_router(sim_routes.router)
    app.include_router(soar_routes.router)

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
