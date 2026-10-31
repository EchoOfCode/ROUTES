# ROUTES test-runner sandbox image (fixed entrypoint: test_runner.main).
# Executes a declarative test plan against one application under test.
FROM python:3.12.8-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 HOME=/tmp
RUN groupadd -g 10001 sandbox && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin sandbox
COPY packages/shared /build/shared
RUN pip install --no-cache-dir /build/shared "httpx>=0.27,<1" "pytest>=8" && rm -rf /build
COPY services/test_runner/test_runner /srv/test_runner
COPY services/test_runner/tests /srv/test_runner_tests
LABEL org.routes.role="test-runner"
WORKDIR /srv
USER 10001:10001
CMD ["python", "-m", "test_runner.main"]
