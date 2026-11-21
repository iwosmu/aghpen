# syntax=docker/dockerfile:1
# Czujka product image: the API, the scan engine and the web UI in one binary.
# Build context: the repository root.
#   docker build -f deploy/Dockerfile -t czujka:dev .

ARG GO_VERSION=1.27
ARG NODE_VERSION=24
ARG ALPINE_VERSION=3.22

# ---- 1. web UI ----
FROM node:${NODE_VERSION}-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- 2. static Go binary with the UI embedded (build tag embedui) ----
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist/ ./web/dist/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -tags embedui -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/czujka ./cmd/czujka

# ---- 3. runtime: nmap, non-root ----
FROM alpine:${ALPINE_VERSION}
# Raw sockets without root: file capabilities.
#  - nmap gets cap_net_raw and cap_net_admin, so it can send SYN, ICMP and ARP probes (nmap --privileged).
#  - czujka gets cap_net_raw only: at start it opens one raw ICMP socket to find out whether raw
#    sockets work, and then runs nmap in SYN mode; without it the engine falls back to nmap -sT.
# The container must keep NET_RAW and NET_ADMIN in its bounding set (docker-compose.yml: cap_add),
# and must not set no-new-privileges, which would ignore file capabilities.
RUN apk add --no-cache nmap nmap-scripts libcap ca-certificates tzdata \
 && addgroup -S -g 10001 czujka && adduser -S -u 10001 -G czujka -h /var/lib/czujka czujka \
 && mkdir -p /var/lib/czujka && chown -R czujka:czujka /var/lib/czujka \
 && setcap cap_net_raw,cap_net_admin+eip "$(readlink -f /usr/bin/nmap)"
COPY --from=build /out/czujka /usr/local/bin/czujka
RUN setcap cap_net_raw+ep /usr/local/bin/czujka && apk del libcap
ENV CZUJKA_LISTEN=:8080 \
    CZUJKA_MASTER_KEY_FILE=/var/lib/czujka/master.key \
    NMAP_PRIVILEGED=1
USER czujka:czujka
WORKDIR /var/lib/czujka
VOLUME ["/var/lib/czujka"]
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 CMD ["czujka", "healthcheck"]
ENTRYPOINT ["czujka"]
CMD ["serve"]
