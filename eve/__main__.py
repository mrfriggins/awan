"""Run the EVE API server:  python -m eve  (or use uvicorn eve.asgi:app)."""
from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("EVE_HOST", "0.0.0.0")
    port = int(os.environ.get("EVE_PORT", "8000"))
    uvicorn.run("eve.asgi:app", host=host, port=port,
                log_level=os.environ.get("EVE_LOG_LEVEL", "info").lower())


if __name__ == "__main__":
    main()
