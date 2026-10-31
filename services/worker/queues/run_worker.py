"""RQ worker entrypoint.

Each worker process listens on the queues given on the command line, so
discovery and source analysis can run concurrently in separate processes.
"""

from __future__ import annotations

import logging
import sys

from redis import Redis
from rq import Queue, Worker

from app.core.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

QUEUES = ("discovery", "source", "results", "remediate")


def main(argv: list[str]) -> int:
    names = [n for n in argv if n in QUEUES] or list(QUEUES)
    connection = Redis.from_url(get_settings().redis_url)
    queues = [Queue(name, connection=connection) for name in names]
    if "remediate" in names:
        # Publish remediation jobs staged in the outbox while Redis or the
        # workers were unavailable (e.g. runs recovered at startup).
        from app.core.db import get_sessionmaker
        from app.services import outbox

        with get_sessionmaker()() as db:
            outbox.relay_safely(db)
    Worker(queues, connection=connection).work(with_scheduler=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
