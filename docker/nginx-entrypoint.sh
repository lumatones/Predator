#!/bin/sh
# ── Predator Nginx Entrypoint ──
# Runs before nginx starts (sourced by official entrypoint from /docker-entrypoint.d/).
# 1. If Let's Encrypt cert exists → symlink to /etc/nginx/certs
# 2. Otherwise → generate self-signed cert so nginx can start
# 3. Copy config template → final nginx config

set -e

DOMAIN="${DOMAIN:-localhost}"
CERT_DIR="/etc/nginx/certs"
LE_LIVE="/etc/letsencrypt/live/${DOMAIN}"

mkdir -p "${CERT_DIR}"

if [ -f "${LE_LIVE}/fullchain.pem" ] && [ -f "${LE_LIVE}/privkey.pem" ]; then
  echo "[nginx-entrypoint] Using Let's Encrypt certificate for ${DOMAIN}"
  ln -sf "${LE_LIVE}/fullchain.pem" "${CERT_DIR}/fullchain.pem"
  ln -sf "${LE_LIVE}/privkey.pem"  "${CERT_DIR}/privkey.pem"
  ln -sf "${LE_LIVE}/chain.pem"    "${CERT_DIR}/chain.pem"
else
  if [ ! -f "${CERT_DIR}/fullchain.pem" ] || [ ! -f "${CERT_DIR}/privkey.pem" ]; then
    echo "[nginx-entrypoint] Generating self-signed certificate for ${DOMAIN}"
    openssl req -x509 -nodes -days 90 -newkey rsa:2048 \
      -keyout "${CERT_DIR}/privkey.pem" \
      -out "${CERT_DIR}/fullchain.pem" \
      -subj "/CN=${DOMAIN}" 2>/dev/null
    cp "${CERT_DIR}/fullchain.pem" "${CERT_DIR}/chain.pem"
    echo "[nginx-entrypoint] Self-signed cert ready. Replace with Let's Encrypt."
  fi
fi

# Copy config template to active config
cp /etc/nginx/conf.d/default.conf.template /etc/nginx/conf.d/default.conf

echo "[nginx-entrypoint] Ready."
