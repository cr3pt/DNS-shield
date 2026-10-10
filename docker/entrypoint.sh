#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

set -e

if [ "$(id -u)" = "0" ] && [ "${DNSSHIELD_RUN_AS_NONROOT:-}" = "1" ]; then
    chown -R dnsshield:dnsshield /data 2>/dev/null || true
    if [ -d /etc/letsencrypt ]; then
        chown -R dnsshield:dnsshield /etc/letsencrypt 2>/dev/null || true
    fi
    exec gosu dnsshield "$@"
fi

exec "$@"
