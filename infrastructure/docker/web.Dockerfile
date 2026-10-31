# ROUTES web interface (Next.js standalone build). Build context: repo root.
FROM oven/bun:1 AS build
WORKDIR /src
COPY apps/web/package.json apps/web/bun.lock* ./
RUN bun install --frozen-lockfile
COPY apps/web ./
ARG API_INTERNAL_URL=http://api:8000
ENV API_INTERNAL_URL=${API_INTERNAL_URL} NEXT_TELEMETRY_DISABLED=1
RUN bun run build

FROM node:22-alpine
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -g 10001 web && adduser -u 10001 -G web -D -H web
WORKDIR /app
COPY --from=build --chown=10001:10001 /src/.next/standalone ./
COPY --from=build --chown=10001:10001 /src/.next/static ./.next/static
COPY --from=build --chown=10001:10001 /src/public ./public
USER 10001:10001
EXPOSE 3000
CMD ["node", "server.js"]
