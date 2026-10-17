# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from unittest.mock import patch

import requests

from app.url_ping import UrlPingTask


def test_start_does_not_ping_when_disabled(config_store):
    task = UrlPingTask(config_store)
    with patch("app.url_ping.requests.get") as mock_get:
        task.start()
        try:
            mock_get.assert_not_called()
        finally:
            task.stop()


def test_start_pings_immediately_when_enabled(config_store):
    config_store.mutate(
        lambda d: d.setdefault("url_ping", {}).update(
            {"enabled": True, "url": "https://1.1.1.1/ping"}
        )
    )
    task = UrlPingTask(config_store)
    with patch("app.url_ping.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        task.start()
        try:
            mock_get.assert_called_once()
            args, _ = mock_get.call_args
            assert args[0] == "https://1.1.1.1/ping"
        finally:
            task.stop()


def test_ping_once_swallows_request_errors(config_store):
    config_store.mutate(
        lambda d: d.setdefault("url_ping", {}).update(
            {"enabled": True, "url": "https://1.1.1.1/ping"}
        )
    )
    task = UrlPingTask(config_store)
    with patch("app.url_ping.requests.get", side_effect=requests.RequestException("boom")):
        task._ping_once()


def test_ping_once_refuses_a_url_that_resolves_to_a_private_address(config_store):
    config_store.mutate(
        lambda d: d.setdefault("url_ping", {}).update(
            {"enabled": True, "url": "http://127.0.0.1:9999/ping"}
        )
    )
    task = UrlPingTask(config_store)
    with patch("app.url_ping.requests.get") as mock_get:
        task._ping_once()
        mock_get.assert_not_called()
