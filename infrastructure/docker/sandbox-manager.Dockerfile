# ROUTES Sandbox Manager. Build context: repo root.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN groupadd -g 10001 routes && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin routes
COPY packages/shared /build/shared
RUN pip install --no-cache-dir /build/shared "fastapi>=0.115,<1" "uvicorn>=0.30" "httpx>=0.27" "pytest>=8" \
    && rm -rf /build && mkdir -p /data/uploads && chown -R 10001:10001 /data

COPY services/sandbox_manager /srv/sandbox_manager
WORKDIR /srv/sandbox_manager
USER 10001:10001
EXPOSE 8100
CMD ["uvicorn", "manager.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8100"]
