FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY config ./config

RUN mkdir -p /data
VOLUME ["/data"]

ENV DNSSHIELD_CONFIG=/data/config.yaml \
    DNSSHIELD_DATA_DIR=/data \
    PYTHONUNBUFFERED=1

# 53/udp+tcp: DNS. 3000/tcp: web UI.
# Binding port 53 requires the CAP_NET_BIND_SERVICE capability (or root,
# which is what this image runs as by default - the same approach used by
# the official AdGuard Home and Pi-hole images). If you prefer a rootless
# container, add `cap_add: [NET_BIND_SERVICE]` and a non-root `user:` in
# your compose override instead.
EXPOSE 53/udp 53/tcp 3000/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import socket; s=socket.create_connection(('127.0.0.1',3000),timeout=3); s.close()"

ENTRYPOINT ["python", "-m", "app.main"]
