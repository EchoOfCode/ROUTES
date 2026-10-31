# ROUTES build-runner sandbox image (fixed entrypoint: build_runner.main).
# Installs, builds and starts a developer's Next.js application inside a
# disposable sandbox. It never uses the repository's Dockerfile or Compose
# files. Started only by the Sandbox Manager, as UID 10001, read-only root,
# no capabilities, internal networks only. Build context: repo root.
FROM node:20.18.1-bookworm-slim AS node

FROM python:3.12.8-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 HOME=/home/sandbox \
    NEXT_TELEMETRY_DISABLED=1 NPM_CONFIG_UPDATE_NOTIFIER=false
RUN apt-get update && apt-get install -y --no-install-recommends git postgresql-client ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 sandbox && useradd -u 10001 -g 10001 -d /home/sandbox -M -s /usr/sbin/nologin sandbox
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && node --version && npm --version
COPY packages/shared /build/shared
RUN pip install --no-cache-dir /build/shared "httpx>=0.27,<1" "pytest>=8" && rm -rf /build \
    && mkdir -p /home/sandbox /work && chown 10001:10001 /home/sandbox /work
# Reused, not reimplemented: the analyzer's safe archive extraction and gateway import client.
COPY services/source_analyzer/__init__.py /srv/source_analyzer/__init__.py
COPY services/source_analyzer/acquisition /srv/source_analyzer/acquisition
COPY services/build_runner/build_runner /srv/build_runner
COPY services/build_runner/tests /srv/build_runner_tests
LABEL org.routes.role="build-runner" org.routes.node="20.18.1"
WORKDIR /srv
USER 10001:10001
CMD ["python", "-m", "build_runner.main"]
