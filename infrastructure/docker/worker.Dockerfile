# ROUTES background worker (RQ). Has no Docker access: sandboxes are requested
# from the Sandbox Manager over HTTP. Build context: repo root.
ARG BASE_IMAGE=routes/api:local
FROM ${BASE_IMAGE}

USER 0
COPY services/worker /srv/worker
ENV PYTHONPATH=/srv:/srv/api
WORKDIR /srv
USER 10001:10001
CMD ["python", "-m", "worker.queues.run_worker"]
