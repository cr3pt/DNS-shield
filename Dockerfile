# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        nginx \
        certbot \
        gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r dnsshield && useradd -r -g dnsshield -d /app -s /usr/sbin/nologin dnsshield

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY config ./config
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /data /etc/nginx/conf.d /var/www/certbot /var/log/nginx /var/lib/nginx \
    && chown -R dnsshield:dnsshield /data /var/www/certbot /var/log/nginx /var/lib/nginx
VOLUME ["/data"]

ENV DNSSHIELD_CONFIG_DB=/data/config.db \
    DNSSHIELD_CONFIG_BACKUP=/data/config.backup.yaml \
    DNSSHIELD_CONFIG=/data/config.yaml \
    DNSSHIELD_DATA_DIR=/data \
    PYTHONUNBUFFERED=1

EXPOSE 53/udp 53/tcp 3000/tcp 80/tcp 443/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -m app.healthcheck

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "app.main"]
