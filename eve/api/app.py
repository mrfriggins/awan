"""FastAPI application factory."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ..clock import Clock
from ..config import Settings
from ..factory import Engine, build_engine
from .routes import router

_FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend"


def create_app(engine: Optional[Engine] = None,
               settings: Optional[Settings] = None,
               clock: Optional[Clock] = None) -> FastAPI:
    app = FastAPI(title="EVE Offensive Execution Engine", version="1.0.0",
                  description="Autonomous, authorized-lab security-operations "
                              "executor (offline simulator).")
    app.state.engine = engine or build_engine(settings, clock=clock)
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                       allow_headers=["*"])

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    app.include_router(router)

    if _FRONTEND.is_dir():
        app.mount("/app", StaticFiles(directory=str(_FRONTEND), html=True),
                  name="frontend")

        @app.get("/")
        def index():
            return FileResponse(str(_FRONTEND / "index.html"))

    return app
