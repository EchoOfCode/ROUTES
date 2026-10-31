"""Startup tasks run by the one-shot ``migrate`` service before the API and
workers start: apply migrations, then reconcile work interrupted by a restart."""

import logging
import subprocess
import sys

from app.core.db import get_sessionmaker
from app.services.lifecycle import reconcile_after_restart

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("routes.startup")


def main() -> int:
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True)
    with get_sessionmaker()() as db:
        n = reconcile_after_restart(db)
    log.info("startup reconciliation complete; %d interrupted assessment(s) marked failed", n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
