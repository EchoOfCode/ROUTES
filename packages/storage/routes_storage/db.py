"""SQLite engine, pragmas and schema versioning."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from routes_storage.models import Base
from routes_storage.paths import restrict

SCHEMA_VERSION = 1


def make_engine(path: Path) -> Engine:
    engine = create_engine(f"sqlite:///{path.as_posix()}", future=True,
                           connect_args={"timeout": 15, "check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()

    return engine


def migrate(engine: Engine) -> int:
    """Create or upgrade the schema. Returns the resulting version."""
    with engine.begin() as conn:
        version = conn.execute(text("PRAGMA user_version")).scalar() or 0
        if version > SCHEMA_VERSION:
            raise RuntimeError("This ROUTES database was created by a newer version of ROUTES.")
        if version < 1:
            Base.metadata.create_all(conn)
            conn.execute(text(f"PRAGMA user_version={SCHEMA_VERSION}"))
    return SCHEMA_VERSION


class Database:
    def __init__(self, path: Path):
        self.path = path
        new = not path.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = make_engine(path)
        migrate(self.engine)
        if new:
            restrict(path, 0o600)
        self.sessionmaker = sessionmaker(self.engine, expire_on_commit=False)

    def session(self) -> Session:
        return self.sessionmaker()

    def close(self) -> None:
        self.engine.dispose()
