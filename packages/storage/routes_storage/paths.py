"""The ~/.routes directory layout.

    ~/.routes/
      routes.db          SQLite: projects, assessments, results
      config.toml        CLI settings
      engine.env         engine secrets (only when ROUTES generated them)
      history            interactive prompt history
      reports/<project>/<assessment>/report.{md,html} findings.json
      cache/             temporary packed sources (deleted after upload)
      logs/
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RoutesHome:
    root: Path

    @property
    def db(self) -> Path:
        return self.root / "routes.db"

    @property
    def config(self) -> Path:
        return self.root / "config.toml"

    @property
    def engine_env(self) -> Path:
        return self.root / "engine.env"

    @property
    def history(self) -> Path:
        return self.root / "history"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @property
    def cache(self) -> Path:
        return self.root / "cache"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    def report_dir(self, project_id: str, assessment_id: str) -> Path:
        return self.reports / project_id / assessment_id

    def ensure(self) -> None:
        for d in (self.root, self.reports, self.cache, self.logs):
            d.mkdir(parents=True, exist_ok=True)
            restrict(d, 0o700)

    @property
    def initialised(self) -> bool:
        return self.db.exists() and self.config.exists()


def home() -> RoutesHome:
    override = os.environ.get("ROUTES_HOME")
    return RoutesHome(Path(override).expanduser() if override else Path.home() / ".routes")


def restrict(path: Path, mode: int) -> None:
    """Owner-only permissions on POSIX. On Windows the user profile ACL applies."""
    if sys.platform != "win32":
        try:
            os.chmod(path, mode)
        except OSError:
            pass
