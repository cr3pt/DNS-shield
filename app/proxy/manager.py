from __future__ import annotations

import logging
import subprocess
import threading
import time

from app.proxy import nginx_manager

logger = logging.getLogger("dnsshield.proxy")


class ProxyManager:
    def __init__(self, config_store):
        self._config = config_store
        self._process: subprocess.Popen | None = None
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None

    def start(self) -> None:
        if not self._config.get("proxy", "enabled", default=False):
            return
        self._regenerate_all()
        self._start_nginx_process()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, name="nginx-monitor", daemon=True)
        self._monitor_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._process is not None:
            self._process.terminate()

    def _regenerate_all(self) -> None:
        nginx_manager.CONF_DIR.mkdir(parents=True, exist_ok=True)
        count = 0
        for domain in self._config.get("proxy", "domains", default=[]) or []:
            if not domain.get("enabled", True):
                continue
            rendered = nginx_manager.render_domain(domain)
            nginx_manager.conf_path_for(domain["id"]).write_text(rendered)
            count += 1
        logger.info("regenerated %d nginx domain config(s)", count)

        test = nginx_manager.test_config()
        if not test["ok"]:
            logger.warning("regenerated nginx config failed `nginx -t`: %s", test["stderr"] or test["stdout"])

    def _start_nginx_process(self) -> None:
        try:
            self._process = subprocess.Popen(["nginx", "-g", "daemon off;"])
            logger.info("nginx started (pid %d)", self._process.pid)
        except OSError as exc:
            logger.error("could not start nginx: %s", exc)
            self._process = None

    def _monitor_loop(self) -> None:
        while not self._stop_event.wait(2.0):
            if self._process is not None and self._process.poll() is not None:
                logger.warning("nginx exited unexpectedly (code %s), restarting", self._process.returncode)
                self._start_nginx_process()
