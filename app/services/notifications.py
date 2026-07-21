import logging
import smtplib
import ssl
from email.message import EmailMessage

import httpx

from config import settings

logger = logging.getLogger(__name__)


async def send_email(to: str, subject: str, body: str) -> bool:
    if not settings.smtp_host:
        logger.warning("SMTP not configured, skipping email notification")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg.set_content(body)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            server.starttls(context=context)
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error("Failed to send email: %s", e)
        return False


async def send_slack(webhook_url: str, message: str) -> bool:
    if not webhook_url:
        logger.warning("Slack webhook not configured")
        return False

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(webhook_url, json={"text": message})
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.error("Failed to send Slack notification: %s", e)
            return False
