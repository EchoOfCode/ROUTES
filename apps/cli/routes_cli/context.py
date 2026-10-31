"""Runtime context shared by direct commands and the interactive interface."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from routes_core.engine import EngineClient
from routes_storage.config import Config, EngineSettings, engine_settings, generate_engine_env, read_env_file
from routes_storage.db import Database
from routes_storage.paths import RoutesHome, home
from sqlalchemy.orm import Session

COMPOSE_MARKER = "sandbox-manager:"


@dataclass
class InitReport:
    home: Path
    created_home: bool
    created_db: bool
    compose_file: Path | None
    env_file: Path | None
    env_source: str            # "existing" | "repository .env" | "generated" | "missing"
    notes: list[str] = field(default_factory=list)


def find_compose_file() -> Path | None:
    candidates: list[Path] = []
    env = os.environ.get("ROUTES_COMPOSE_FILE")
    if env:
        candidates.append(Path(env).expanduser())
    here = Path(__file__).resolve()
    candidates += [p / "docker-compose.yml" for p in here.parents]
    candidates += [p / "docker-compose.yml" for p in [Path.cwd(), *Path.cwd().parents]]
    for c in candidates:
        try:
            if c.is_file() and COMPOSE_MARKER in c.read_text(encoding="utf-8", errors="ignore"):
                return c.resolve()
        except OSError:
            continue
    return None


def initialise(h: RoutesHome | None = None) -> InitReport:
    """Create ~/.routes, the database and config; locate the engine. Idempotent."""
    h = h or home()
    created_home = not h.root.exists()
    h.ensure()
    created_db = not h.db.exists()
    Database(h.db).close()
    cfg = Config.load(h)
    notes: list[str] = []

    compose = Path(cfg.engine.compose_file) if cfg.engine.compose_file else None
    if compose is None or not compose.is_file():
        compose = find_compose_file()
        cfg.engine.compose_file = str(compose) if compose else ""
    if compose is None:
        notes.append("The ROUTES engine definition (docker-compose.yml) was not found. "
                     "Set ROUTES_COMPOSE_FILE to its path and run `routes init` again.")

    env_source = "existing"
    env_file = Path(cfg.engine.env_file) if cfg.engine.env_file else None
    if env_file is None or not env_file.is_file():
        repo_env = compose.parent / ".env" if compose else None
        if repo_env and repo_env.is_file() and read_env_file(repo_env).get("SANDBOX_MANAGER_TOKEN"):
            env_file, env_source = repo_env, "repository .env"
            notes.append(f"Using the engine secrets in {repo_env} (shared with the web stack).")
        else:
            generate_engine_env(h.engine_env)
            env_file, env_source = h.engine_env, "generated"
        cfg.engine.env_file = str(env_file)
    cfg.save(h)
    return InitReport(h.root, created_home, created_db, compose, env_file, env_source, notes)


class Context:
    def __init__(self, h: RoutesHome, cfg: Config, *, no_animation: bool = False):
        self.home = h
        self.config = cfg
        self.no_animation = no_animation or cfg.ui.reduced_motion or not cfg.ui.animations
        self._db: Database | None = None
        self.init_report: InitReport | None = None

    @classmethod
    def load(cls, *, no_animation: bool = False, auto_init: bool = True) -> "Context":
        h = home()
        report = None
        if auto_init and not h.initialised:
            report = initialise(h)
        ctx = cls(h, Config.load(h), no_animation=no_animation)
        ctx.init_report = report
        return ctx

    # ------------------------------------------------------------- storage
    @property
    def db(self) -> Database:
        if self._db is None:
            self._db = Database(self.home.db)
        return self._db

    def session(self) -> Session:
        return self.db.session()

    def save_config(self) -> None:
        self.config.save(self.home)

    # -------------------------------------------------------------- engine
    @property
    def engine(self) -> EngineSettings:
        return engine_settings(self.config)

    def engine_client(self) -> EngineClient:
        es = self.engine
        return EngineClient(es.url, es.token)

    def dev_allow_hosts(self) -> frozenset[str]:
        raw = ",".join([self.engine.dev_allow_hosts, os.environ.get("GATEWAY_DEV_ALLOW_HOSTS", "")])
        return frozenset(h.strip().lower() for h in raw.split(",") if h.strip())

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
