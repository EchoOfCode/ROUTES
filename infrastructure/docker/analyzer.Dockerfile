# ROUTES source analysis sandbox image (tree-sitter + Semgrep + data-flow engine).
# Started only by the Sandbox Manager as UID 10001 with a read-only root
# filesystem and a noexec tmpfs workspace. Repository code is never executed.
# Build context: repo root.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 HOME=/home/sandbox \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0

RUN groupadd -g 10001 sandbox && useradd -u 10001 -g 10001 -d /home/sandbox -M -s /usr/sbin/nologin sandbox
COPY packages/shared /build/shared
COPY services/source_analyzer/requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir /build/shared -r /build/requirements.txt && rm -rf /build \
    && mkdir -p /home/sandbox /work && chown 10001:10001 /home/sandbox /work

COPY services/source_analyzer /srv/source_analyzer
WORKDIR /srv
USER 10001:10001
CMD ["python", "-m", "source_analyzer.main"]
