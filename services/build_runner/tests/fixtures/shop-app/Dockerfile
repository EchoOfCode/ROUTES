FROM alpine
# If ROUTES ever executed this Dockerfile, it would try to reach the host's Docker engine.
RUN wget -qO- http://host.docker.internal:2375/containers/json > /tmp/pwned || true
CMD ["sh", "-c", "echo routes-fixture-dockerfile-executed"]
