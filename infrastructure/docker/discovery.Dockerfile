# ROUTES discovery sandbox image (HTTP crawler + Playwright Chromium).
# Started only by the Sandbox Manager, as UID 10001 with a read-only root
# filesystem, no capabilities and an internal-only network. Build context: repo root.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright HOME=/home/sandbox

RUN groupadd -g 10001 sandbox && useradd -u 10001 -g 10001 -d /home/sandbox -M -s /usr/sbin/nologin sandbox
COPY packages/shared /build/shared
COPY services/discovery/requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir /build/shared -r /build/requirements.txt \
    && python -m playwright install --with-deps chromium \
    && rm -rf /build /var/lib/apt/lists/* && mkdir -p /home/sandbox && chown 10001:10001 /home/sandbox

COPY services/discovery /srv/discovery
WORKDIR /srv
USER 10001:10001
CMD ["python", "-m", "discovery.main"]
