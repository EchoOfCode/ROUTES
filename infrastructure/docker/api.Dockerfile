# ROUTES API (also used for the one-shot migrate service). Build context: repo root.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd -g 10001 routes && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin routes

COPY packages/shared /build/shared
COPY services/api /srv/api
RUN pip install --no-cache-dir /build/shared "/srv/api[test]" && rm -rf /build /srv/api/build \
    && mkdir -p /data/uploads && chown -R 10001:10001 /data

WORKDIR /srv/api
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
