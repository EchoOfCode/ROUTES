"""Startup tasks run by the one-shot ``migrate`` service before the API and
workers start: apply migrations, then reconcile work interrupted by a restart."""

import logging
import subprocess
import sys

from app.core.db import get_sessionmaker
from app.services import artifacts, remediation_store
from app.services.lifecycle import reconcile_after_restart

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("routes.startup")


def main() -> int:
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True)
    with get_sessionmaker()() as db:
        n = reconcile_after_restart(db)
    log.info("startup reconciliation complete; %d interrupted assessment(s) marked failed", n)
    with get_sessionmaker()() as db:
        # Remediation runs survive restarts: interrupted ones are re-dispatched
        # through the outbox (published by worker-remediate when it starts).
        recovered = remediation_store.recover_interrupted(db)
        purged = artifacts.purge_expired(db)
    log.info("remediation recovery: %d run(s) re-dispatched, %d expired artifact(s) purged", recovered, purged)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
