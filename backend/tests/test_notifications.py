import pytest

from app.config import settings
from app.services.notifications import send_email, send_slack


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
    assert request.json() == {"text": "Test message"}


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
