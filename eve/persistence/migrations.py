"""Lightweight migration runner (create-all + schema stamp)."""
from __future__ import annotations

from sqlalchemy import select

from .db import Database
from .tables import Base, SchemaVersion

SCHEMA_VERSION = 1


def apply(db: Database) -> int:
    Base.metadata.create_all(db.engine)
    with db.session() as s:
        existing = s.execute(
            select(SchemaVersion).where(SchemaVersion.version == SCHEMA_VERSION)
        ).scalar_one_or_none()
        if existing is None:
            s.add(SchemaVersion(version=SCHEMA_VERSION))
    return SCHEMA_VERSION
