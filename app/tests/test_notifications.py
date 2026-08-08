import json
from unittest.mock import MagicMock, patch

import pytest

from config import settings
from services.notifications import send_email, send_slack


@pytest.mark.asyncio
async def test_send_email_no_smtp():
    original = settings.smtp_host
    settings.smtp_host = ""
    try:
        result = await send_email("test@example.com", "Subject", "Body")
        assert result is False
    finally:
        settings.smtp_host = original


@pytest.mark.asyncio
async def test_send_email_smtp_success():
    original_host = settings.smtp_host
    original_user = settings.smtp_user
    settings.smtp_host = "smtp.example.com"
    settings.smtp_user = ""
    try:
        with patch("services.notifications.smtplib.SMTP") as mock_smtp:
            server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = server

            result = await send_email("test@example.com", "Subject", "Body")

        assert result is True
        server.starttls.assert_called_once()
        server.login.assert_not_called()
        server.send_message.assert_called_once()
    finally:
        settings.smtp_host = original_host
        settings.smtp_user = original_user


@pytest.mark.asyncio
async def test_send_email_smtp_with_login():
    original_host = settings.smtp_host
    original_user = settings.smtp_user
    original_password = settings.smtp_password
    settings.smtp_host = "smtp.example.com"
    settings.smtp_user = "user@example.com"
    settings.smtp_password = "secret"
    try:
        with patch("services.notifications.smtplib.SMTP") as mock_smtp:
            server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = server

            result = await send_email("test@example.com", "Subject", "Body")

        assert result is True
        server.login.assert_called_once_with("user@example.com", "secret")
    finally:
        settings.smtp_host = original_host
        settings.smtp_user = original_user
        settings.smtp_password = original_password


@pytest.mark.asyncio
async def test_send_email_smtp_failure():
    original_host = settings.smtp_host
    settings.smtp_host = "smtp.example.com"
    try:
        with patch("services.notifications.smtplib.SMTP") as mock_smtp:
            mock_smtp.return_value.__enter__.return_value = MagicMock(
                starttls=MagicMock(side_effect=RuntimeError("tls failed"))
            )

            result = await send_email("test@example.com", "Subject", "Body")

        assert result is False
    finally:
        settings.smtp_host = original_host


@pytest.mark.asyncio
async def test_send_slack_no_webhook():
    original = settings.slack_webhook_url
    settings.slack_webhook_url = ""
    try:
        result = await send_slack("", "Hello")
        assert result is False
    finally:
        settings.slack_webhook_url = original


@pytest.mark.asyncio
async def test_send_slack_success(httpx_mock):
    webhook = "https://hooks.slack.com/services/xxx/yyy/zzz"
    httpx_mock.add_response(
        url=webhook,
        method="POST",
        status_code=200,
        text="ok",
    )
    result = await send_slack(webhook, "Test message")
    assert result is True

    request = httpx_mock.get_request()
    assert request is not None
    assert json.loads(request.read()) == {"text": "Test message"}


@pytest.mark.asyncio
async def test_send_slack_http_error(httpx_mock):
    webhook = "https://hooks.slack.com/services/xxx/yyy/zzz"
    httpx_mock.add_response(
        url=webhook,
        method="POST",
        status_code=403,
    )
    result = await send_slack(webhook, "Test")
    assert result is False


@pytest.mark.asyncio
async def test_send_slack_network_error(httpx_mock):
    webhook = "https://hooks.slack.com/services/xxx/yyy/zzz"
    httpx_mock.add_exception(
        ConnectionError("Network error"),
        url=webhook,
        method="POST",
    )
    result = await send_slack(webhook, "Test")
    assert result is False
