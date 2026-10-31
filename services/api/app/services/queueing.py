"""RQ enqueue helpers. Jobs are referenced by import path so the API never
imports worker code. RQ job ids equal assessment_job ids, so enqueuing the same
work twice is a no-op at the queue level as well as the database level.
"""

import uuid

from rq import Queue, Retry

from app.core.redis import get_redis

JOB_FUNCS = {
    "discovery": "worker.jobs.discovery.run_discovery_job",
    "source": "worker.jobs.source.run_source_job",
    "results": "worker.jobs.results.run_results_job",
    "remediate": "worker.jobs.remediate.run_remediate_job",
}

JOB_TIMEOUTS = {"discovery": 900, "source": 1200, "results": 300, "remediate": 1800}


def enqueue_job(kind: str, job_id: uuid.UUID, **kwargs) -> None:
    queue = Queue(kind, connection=get_redis())
    existing = queue.fetch_job(str(job_id))
    if existing is not None and existing.get_status(refresh=True) in ("queued", "started", "deferred", "scheduled"):
        return
    queue.enqueue(
        JOB_FUNCS[kind],
        job_id=str(job_id),
        kwargs={"job_id": str(job_id), **kwargs},
        job_timeout=JOB_TIMEOUTS[kind],
        result_ttl=3600,
        failure_ttl=24 * 3600,
        # Only infrastructure errors raise out of jobs; target failures are
        # recorded as job results, so this retry never repeats a crawl that
        # already reached the target.
        retry=Retry(max=1, interval=10) if kind != "results" else Retry(max=2, interval=5),
    )


def cancel_job(kind: str, job_id: uuid.UUID) -> None:
    queue = Queue(kind, connection=get_redis())
    job = queue.fetch_job(str(job_id))
    if job is not None and job.get_status(refresh=True) in ("queued", "deferred", "scheduled"):
        job.cancel()
