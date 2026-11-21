# syntax=docker/dockerfile:1
# Czujka product image. Build context: the repository root.
#   docker build -f deploy/Dockerfile -t czujka:dev .

ARG GO_VERSION=1.27
ARG NODE_VERSION=22
ARG ALPINE_VERSION=3.22

# ---- 1. web UI (built only when web/ exists in the context) ----
FROM node:${NODE_VERSION}-alpine AS web
WORKDIR /src
COPY . .
RUN mkdir -p /out \
 && if [ -f web/package.json ]; then \
      cd web && (npm ci || npm install) && npm run build && cp -r dist/. /out/; \
    else \
      echo "web/ is not in the build context: the image has no UI, only the API"; \
    fi

# ---- 2. static Go binary ----
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The built UI, for a package under web/ that embeds web/dist.
COPY --from=web /out/ ./web/dist/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/czujka ./cmd/czujka

# ---- 3. runtime: nmap, non-root ----
FROM alpine:${ALPINE_VERSION}
# nmap gets raw sockets through file capabilities, so the process runs as a normal user.
# The container needs only NET_RAW and NET_ADMIN in its bounding set (see docker-compose.yml).
RUN apk add --no-cache nmap nmap-scripts libcap ca-certificates tzdata \
 && addgroup -S -g 10001 czujka && adduser -S -u 10001 -G czujka -h /var/lib/czujka czujka \
 && mkdir -p /var/lib/czujka /app/web && chown -R czujka:czujka /var/lib/czujka \
 && setcap cap_net_raw,cap_net_admin+eip "$(readlink -f /usr/bin/nmap)" \
 && apk del libcap
COPY --from=build /out/czujka /usr/local/bin/czujka
COPY --from=web /out/ /app/web/
ENV CZUJKA_LISTEN=:8080 \
    CZUJKA_WEB_DIR=/app/web \
    CZUJKA_MASTER_KEY_FILE=/var/lib/czujka/master.key \
    NMAP_PRIVILEGED=1
USER czujka:czujka
WORKDIR /var/lib/czujka
VOLUME ["/var/lib/czujka"]
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 CMD ["czujka", "healthcheck"]
ENTRYPOINT ["czujka"]
CMD ["serve"]
