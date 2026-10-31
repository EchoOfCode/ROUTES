# ROUTES disposable database for build-runs: PostgreSQL on tmpfs, run as UID
# 10001 with a read-only root filesystem and no capabilities. Reachable only
# from the build runner of the same run (private, internal network).
FROM postgres:16.6-alpine3.20
RUN addgroup -g 10001 sandbox && adduser -D -u 10001 -G sandbox -h /var/lib/postgresql/data -s /sbin/nologin sandbox
LABEL org.routes.role="build-db" org.routes.postgres="16.6"
USER 10001:10001
