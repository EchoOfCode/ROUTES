# ROUTES background worker (RQ). Has no Docker access: sandboxes are requested
# from the Sandbox Manager over HTTP. Build context: repo root.
FROM routes/api:local

USER 0
COPY services/worker /srv/worker
ENV PYTHONPATH=/srv:/srv/api
WORKDIR /srv
USER 10001:10001
CMD ["python", "-m", "worker.queues.run_worker"]
