#!/bin/sh
# make init: writes deploy/.env with random secrets and a master key.
#
#   ./deploy/init.sh                      new deploy/.env (refuses to replace one)
#   FORCE=1 ./deploy/init.sh              replace it (the old master key is gone: keep a copy first)
#   CZUJKA_ADMIN_EMAIL=... CZUJKA_ALLOWED_NETWORKS=10.0.0.0/8 ./deploy/init.sh
#
# The same script is in the offline bundle, where it writes .env next to it.
set -eu
cd "$(dirname "$0")"
ENV_FILE=.env
if [ -f "$ENV_FILE" ] && [ "${FORCE:-0}" != 1 ]; then
  echo "init: $(pwd)/$ENV_FILE already exists; nothing changed." >&2
  echo "init: FORCE=1 replaces it, and the master key in it is then lost: keep a copy first." >&2
  exit 1
fi
[ -f .env.example ] || { echo "init: .env.example is missing next to this script" >&2; exit 1; }
# Random text from the kernel: letters and digits only, so it is safe in a URL and in sed.
rnd() { od -An -N256 -tx1 /dev/urandom | tr -d ' \n' | cut -c1-"$1"; }
b64key() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }
DB_PW=$(rnd 40)
ADMIN_PW="Cz-$(rnd 20)"
KEY=$(b64key)
EMAIL=${CZUJKA_ADMIN_EMAIL:-admin@czujka.local}
NETS=${CZUJKA_ALLOWED_NETWORKS:-}
umask 077
sed -e "s|^CZUJKA_DB_PASSWORD=.*|CZUJKA_DB_PASSWORD=$DB_PW|" \
    -e "s|^CZUJKA_ADMIN_PASSWORD=.*|CZUJKA_ADMIN_PASSWORD=$ADMIN_PW|" \
    -e "s|^CZUJKA_ADMIN_EMAIL=.*|CZUJKA_ADMIN_EMAIL=$EMAIL|" \
    -e "s|^CZUJKA_MASTER_KEY=.*|CZUJKA_MASTER_KEY=$KEY|" \
    -e "s|^CZUJKA_ALLOWED_NETWORKS=.*|CZUJKA_ALLOWED_NETWORKS=$NETS|" \
    .env.example > "$ENV_FILE.tmp"
mv "$ENV_FILE.tmp" "$ENV_FILE"
chmod 600 "$ENV_FILE"
cat <<EOF
init: wrote $(pwd)/$ENV_FILE (mode 600)
  administrator: $EMAIL
  password:      $ADMIN_PW
  master key:    in CZUJKA_MASTER_KEY. Keep a copy outside this machine: without it
                 the encrypted fields and every backup archive are lost.
Next: make up   (or: docker compose -f docker-compose.yml up -d --wait in the bundle)
EOF
