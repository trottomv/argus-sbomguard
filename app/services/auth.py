import hashlib
import hmac
import logging
import secrets
import string
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import aiosmtplib
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models.auth import ApiKey, LoginToken, User

logger = logging.getLogger(__name__)


def _hash_token(token: str) -> str:
    """Hash a token with HMAC-SHA256 keyed on SECRET_KEY.

    HMAC-SHA256 is a keyed PRF/MAC: the digest is deterministic for a given
    key (so verification is a plain equality lookup on the stored hash) and
    the key is never embedded in the output, so a DB leak alone yields
    nothing. Tokens carry high entropy (login codes ~82 bits, API keys ~192
    bits), so a fast keyed hash is sufficient. Rotating ``SECRET_KEY``
    invalidates every stored hash (token/key lockdown).
    """
    return hmac.new(settings.secret_key.encode(), token.encode(), hashlib.sha256).hexdigest()


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email.strip().lower()))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def seed_admin_user(db: AsyncSession) -> User:
    email = settings.admin_email.strip().lower()
    user = await get_user_by_email(db, email)
    if not user:
        user = User(email=email, is_admin=True)
        db.add(user)
        await db.flush()
    return user


def _generate_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    chars = "".join(secrets.choice(alphabet) for _ in range(16))
    return "-".join(chars[idx : idx + 4] for idx in range(0, 16, 4))


async def create_login_token(db: AsyncSession, user_id: uuid.UUID) -> str:
    raw_code = _generate_code()
    token_hash = _hash_token(raw_code)
    expires_at = datetime.now(UTC) + timedelta(minutes=settings.login_token_expire_minutes)

    lt = LoginToken(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
    db.add(lt)
    await db.flush()

    return raw_code


async def verify_login_token(db: AsyncSession, raw_token: str, email: str) -> User | None:
    token_hash = _hash_token(raw_token)
    now = datetime.now(UTC)

    result = await db.execute(
        select(LoginToken)
        .join(User, LoginToken.user_id == User.id)
        .where(
            LoginToken.token_hash == token_hash,
            LoginToken.used.is_(False),
            LoginToken.expires_at > now,
            User.email == email.strip().lower(),
        )
    )
    lt = result.scalar_one_or_none()
    if not lt:
        return None

    lt.used = True

    user = await get_user_by_id(db, lt.user_id)
    return user


async def send_login_email(email: str, code: str) -> bool | str:
    logger.debug("Generated login code for %s", email)

    if not settings.smtp_host:
        return f"Login code: {code}"

    message = f"From: {settings.smtp_from}\r\nTo: {email}\r\n"
    message += "Subject: Argus SBOM Guard - Login Code\r\n\r\n"
    message += f"Your login code is:\r\n\r\n{code}\r\n\r\n"
    message += f"This code expires in {settings.login_token_expire_minutes} minutes.\r\n"

    try:
        await aiosmtplib.send(
            message.encode(),
            sender=settings.smtp_from,
            recipients=[email],
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            start_tls=False,
        )
    except Exception as e:
        logger.warning("Failed to send login email: %s", e)
        return f"Login code: {code}"

    return True


def generate_api_key() -> tuple[str, str, str]:
    raw = f"argus_{secrets.token_urlsafe(32)}"
    key_hash = _hash_token(raw)
    prefix = raw[:16]
    return raw, key_hash, prefix


def api_key_default_expiry() -> datetime | None:
    """Expiry applied by default to newly created API keys (forced rotation).

    Returns ``None`` when the configured ``API_KEY_TTL_DAYS`` is unset/0, i.e.
    keys do not expire. The default lives here so call sites (web endpoint,
    scripts, UI) share one source of truth while ``create_api_key`` itself
    stays expiry-agnostic.
    """
    ttl_days = settings.api_key_ttl_days
    if not ttl_days:
        return None
    return datetime.now(UTC) + timedelta(days=ttl_days)


async def create_api_key(
    db: AsyncSession,
    user_id: uuid.UUID,
    label: str = "",
    *,
    expires_at: datetime | None = None,
) -> tuple[ApiKey, str]:
    raw, key_hash, prefix = generate_api_key()
    key = ApiKey(
        user_id=user_id,
        key_hash=key_hash,
        key_prefix=prefix,
        label=label,
        expires_at=expires_at,
    )
    db.add(key)
    await db.flush()
    return key, raw


@dataclass
class ApiKeyAuthResult:
    """Outcome of authenticating a raw API key.

    ``user`` is set when the key is valid; ``expired`` distinguishes a key
    that was found but past its ``expires_at`` (so callers can return a
    different 401 message than for an unknown/format-invalid key).
    """

    user: User | None = None
    expired: bool = False

    @property
    def valid(self) -> bool:
        return self.user is not None


async def authenticate_api_key(db: AsyncSession, raw_key: str) -> ApiKeyAuthResult:
    if not raw_key.startswith("argus_"):
        return ApiKeyAuthResult()

    key_hash = _hash_token(raw_key)
    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))
    key = result.scalar_one_or_none()
    if not key:
        return ApiKeyAuthResult()

    if key.expires_at is not None:
        expires_at = key.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            return ApiKeyAuthResult(expired=True)

    key.last_used_at = datetime.now(UTC)
    user = await get_user_by_id(db, key.user_id)
    return ApiKeyAuthResult(user=user)


async def validate_api_key(db: AsyncSession, raw_key: str) -> User | None:
    return (await authenticate_api_key(db, raw_key)).user


async def list_api_keys(db: AsyncSession) -> list[ApiKey]:
    result = await db.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))
    return list(result.scalars().all())


async def revoke_api_key(db: AsyncSession, key_id: uuid.UUID) -> bool:
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id))
    key = result.scalar_one_or_none()
    if not key:
        return False
    await db.delete(key)
    await db.flush()
    return True
