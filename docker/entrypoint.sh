#!/bin/sh
set -e

if [ "$(id -u)" = "0" ] && [ "${DNSSHIELD_RUN_AS_NONROOT:-}" = "1" ]; then
    chown -R dnsshield:dnsshield /data 2>/dev/null || true
    if [ -d /etc/letsencrypt ]; then
        chown -R dnsshield:dnsshield /etc/letsencrypt 2>/dev/null || true
    fi
    exec gosu dnsshield "$@"
fi

exec "$@"
