"""ASGI entrypoint for uvicorn/gunicorn:  uvicorn eve.asgi:app"""
from __future__ import annotations

from .api.app import create_app

app = create_app()
