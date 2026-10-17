# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from unittest.mock import patch

import pytest

from app.notifications import NotificationSender


def test_discord_webhook_refuses_a_url_that_resolves_to_a_private_address(config_store):
    sender = NotificationSender(config_store)
    with patch("app.notifications.requests.post") as mock_post:
        with pytest.raises(ValueError):
            sender._send_webhook({"type": "discord", "url": "http://127.0.0.1:9999/webhook"}, "hi")
        mock_post.assert_not_called()


def test_slack_webhook_refuses_a_url_that_resolves_to_a_private_address(config_store):
    sender = NotificationSender(config_store)
    with patch("app.notifications.requests.post") as mock_post:
        with pytest.raises(ValueError):
            sender._send_webhook({"type": "slack", "url": "http://192.168.1.50/webhook"}, "hi")
        mock_post.assert_not_called()


def test_discord_webhook_sends_to_a_public_url(config_store):
    sender = NotificationSender(config_store)
    with patch("app.notifications.requests.post") as mock_post:
        mock_post.return_value.raise_for_status.return_value = None
        sender._send_webhook({"type": "discord", "url": "https://1.1.1.1/webhook"}, "hi")
        mock_post.assert_called_once()
