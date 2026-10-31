# ROUTES restricted Docker API proxy. Build context: repo root.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --no-cache-dir "h11>=0.14,<1" "pytest>=8"
COPY infrastructure/docker-proxy /srv/docker-proxy
WORKDIR /srv/docker-proxy
# Runs as root only to open the Docker socket; compose drops all capabilities,
# sets no-new-privileges and a read-only root filesystem.
EXPOSE 2375
CMD ["python", "-m", "docker_proxy.server"]
