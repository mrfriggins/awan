"""Database engine and session management. SQLite by default, Postgres-ready."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings


class Database:
    def __init__(self, url: str) -> None:
        connect_args = {}
        if url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
        self.engine = create_engine(url, future=True, connect_args=connect_args)
        self._Session = sessionmaker(bind=self.engine, expire_on_commit=False,
                                     future=True)

    @classmethod
    def from_settings(cls, settings: Settings) -> "Database":
        return cls(settings.database_url)

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()
