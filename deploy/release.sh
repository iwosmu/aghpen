#!/bin/sh
# make release: static linux binaries (amd64, arm64) with the UI embedded,
# each in an archive with the systemd unit, its environment file and the
# bare-metal guide (deploy/systemd).
#
#   make release              -> dist/release/czujka-<version>-linux-<arch>.tar.gz, SHA256SUMS
#   SKIP_WEB=1 make release   reuse web/dist
set -eu
cd "$(dirname "$0")/.."
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
if [ "${SKIP_WEB:-0}" != 1 ] || [ ! -f web/dist/index.html ]; then
  (cd web && npm ci --no-audit --no-fund && npm run build)
fi
rm -rf dist/release; mkdir -p dist/release
for arch in amd64 arm64; do
  d=dist/release/czujka-$VERSION-linux-$arch
  mkdir -p "$d"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -tags embedui -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o "$d/czujka" ./cmd/czujka
  cp deploy/systemd/czujka.service deploy/systemd/czujka.env deploy/systemd/README.md "$d/"
  tar -czf "$d.tar.gz" -C dist/release "$(basename "$d")"
  echo "release: $d.tar.gz"
done
( cd dist/release && (shasum -a 256 ./*.tar.gz 2>/dev/null || sha256sum ./*.tar.gz) > SHA256SUMS )
cat dist/release/SHA256SUMS
