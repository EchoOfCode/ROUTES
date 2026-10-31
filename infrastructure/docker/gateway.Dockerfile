# ROUTES controlled network gateway. Build context: repo root.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd -g 10002 gateway && useradd -u 10002 -g 10002 -M -s /usr/sbin/nologin gateway
COPY packages/shared /build/shared
COPY infrastructure/network-gateway/requirements.txt /build/requirements.txt
RUN pip install --no-cache-dir /build/shared -r /build/requirements.txt && rm -rf /build

COPY infrastructure/network-gateway /srv/network-gateway
WORKDIR /srv/network-gateway
USER 10002:10002
EXPOSE 3128 8080
CMD ["python", "-m", "gateway.main"]
