#!/bin/sh
# make bundle: an offline install archive. It holds the two images (docker
# save), the compose files without build sections, .env.example, init.sh and
# install.sh. The target machine needs docker with the compose plugin, and no
# network access to a registry.
#
#   make bundle            -> dist/czujka-bundle-<version>.tar.gz (+ .sha256)
set -eu
cd "$(dirname "$0")/.."
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
NAME=czujka-bundle-$VERSION
OUT=dist/$NAME
rm -rf "$OUT"; mkdir -p "$OUT"
echo "bundle: building czujka:$VERSION"
CZUJKA_VERSION=$VERSION docker compose -f deploy/docker-compose.yml build czujka
# The database image is built only when it is missing: the tag may be shared.
docker image inspect czujka-db:17 >/dev/null 2>&1 || docker build -t czujka-db:17 deploy/db
echo "bundle: saving the images"
docker save "czujka:$VERSION" czujka-db:17 | gzip -1 > "$OUT/images.tar.gz"
# Compose file without build sections, pinned to this version.
awk '
  /^    build:/ { skip = 1; next }
  skip && /^      / { next }
  { skip = 0; print }
' deploy/docker-compose.yml | sed -e "s|image: czujka:\${CZUJKA_VERSION:-dev}|image: czujka:\${CZUJKA_VERSION:-$VERSION}|" > "$OUT/docker-compose.yml"
cp deploy/docker-compose.scan-network.yml deploy/init.sh "$OUT/"
sed -e "s|^CZUJKA_VERSION=.*|CZUJKA_VERSION=$VERSION|" deploy/.env.example > "$OUT/.env.example"
cat > "$OUT/install.sh" <<'EOF'
#!/bin/sh
# Offline install of Czujka from this bundle: load the images, write .env
# (random secrets, once), start the stack, run the installation check.
set -eu
cd "$(dirname "$0")"
command -v docker >/dev/null || { echo "install: docker is missing"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "install: the docker compose plugin is missing"; exit 1; }
echo "install: loading the images"
gunzip -c images.tar.gz | docker load
[ -f .env ] || sh ./init.sh
# Kernel neighbour table: a scan of a large local network adds one ARP entry
# per probed address, and the limit is shared by the whole host. When it
# overflows the host loses its own entries (DNS stops working). The values fit
# a /16 scanned on-link; czujka doctor computes them for the real scopes.
T3=$(cat /proc/sys/net/ipv4/neigh/default/gc_thresh3 2>/dev/null || echo 0)
if [ "$T3" -gt 0 ] && [ "$T3" -lt 262144 ]; then
  CONF=/etc/sysctl.d/90-czujka-neigh.conf
  LINES="net.ipv4.neigh.default.gc_thresh1 = 32768
net.ipv4.neigh.default.gc_thresh2 = 131072
net.ipv4.neigh.default.gc_thresh3 = 262144"
  echo "install: the kernel neighbour table limit is $T3 (gc_thresh3). Scanning a large local network can overflow it."
  ANSWER=${CZUJKA_WRITE_SYSCTL:-}
  if [ -z "$ANSWER" ] && [ -t 0 ]; then
    printf 'install: write %s with larger limits now? [t/N] ' "$CONF"; read -r ANSWER || ANSWER=n
  fi
  case "$ANSWER" in
    t|T|y|Y|1|tak)
      if [ "$(id -u)" = 0 ]; then printf '%s\n' "$LINES" > "$CONF" && sysctl --system >/dev/null && echo "install: wrote $CONF";
      else printf '%s\n' "$LINES" | sudo tee "$CONF" >/dev/null && sudo sysctl --system >/dev/null && echo "install: wrote $CONF"; fi ;;
    *) echo "install: skipped. To set it later:"; printf '%s\n' "$LINES" | sed 's/^/  /'; echo "  (into $CONF, then: sudo sysctl --system)" ;;
  esac
fi
docker compose -f docker-compose.yml up -d --no-build --pull never --wait
docker compose -f docker-compose.yml exec -T czujka czujka doctor || true
. ./.env
echo "install: Czujka listens on http://${CZUJKA_BIND:-127.0.0.1}:${CZUJKA_PORT:-8080} (administrator: ${CZUJKA_ADMIN_EMAIL})"
EOF
chmod +x "$OUT/install.sh" "$OUT/init.sh"
cat > "$OUT/CZYTAJ.txt" <<EOF
Czujka $VERSION - instalacja offline

Wymagania: docker z wtyczką compose. Dostęp do rejestru obrazów nie jest potrzebny.

1. Rozpakuj: tar -xzf $NAME.tar.gz && cd $NAME
2. Zainstaluj: sh install.sh
   Skrypt ładuje obrazy (docker load), zapisuje .env z losowymi sekretami i kluczem
   głównym (tylko gdy .env nie istnieje), uruchamia stos i sprawdzenie "czujka doctor".
3. Zrób kopię pliku .env poza maszyną: bez klucza głównego dane szyfrowane i kopie
   zapasowe są stracone.

Skanowanie sieci dockera: CZUJKA_SCAN_NETWORK=<sieć> docker compose -f docker-compose.yml -f docker-compose.scan-network.yml up -d --wait
Blokada operatora (zalecana): ustaw CZUJKA_ALLOWED_NETWORKS w .env przed startem.
Kopia zapasowa: docker compose -f docker-compose.yml exec czujka czujka backup
EOF
tar -czf "dist/$NAME.tar.gz" -C dist "$NAME"
( cd dist && shasum -a 256 "$NAME.tar.gz" > "$NAME.tar.gz.sha256" 2>/dev/null || sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )
ls -l "dist/$NAME.tar.gz" | awk '{printf "bundle: %s (%.0f MiB)\n", $NF, $5 / 1048576}'
