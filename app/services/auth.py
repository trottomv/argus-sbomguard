import hashlib
import logging
import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models.user import ApiKey, LoginToken, User

logger = logging.getLogger(__name__)

try:
    import aiosmtplib  # noqa: F811
    HAS_SMTP = True
except ImportError:
    HAS_SMTP = False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


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
    return "-".join(chars[i:i + 4] for i in range(0, 16, 4))


async def create_login_token(db: AsyncSession, user_id: uuid.UUID) -> str:
    raw_code = _generate_code()
    token_hash = _hash_token(raw_code)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.login_token_expire_minutes
    )

    lt = LoginToken(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
    db.add(lt)
    await db.flush()

    return raw_code


async def verify_login_token(db: AsyncSession, raw_token: str) -> User | None:
    token_hash = _hash_token(raw_token)
    now = datetime.now(timezone.utc)

    result = await db.execute(
        select(LoginToken).where(
            LoginToken.token_hash == token_hash,
            LoginToken.used == False,  # noqa: E712
            LoginToken.expires_at > now,
        )
    )
    lt = result.scalar_one_or_none()
    if not lt:
        return None

    lt.used = True

    user = await get_user_by_id(db, lt.user_id)
    return user


async def send_login_email(email: str, code: str) -> bool:
    logger.info("Login code for %s: %s", email, code)

    if not HAS_SMTP or not settings.smtp_host:
        return f"Login code: {code}"

    message = f"From: {settings.smtp_from}\r\nTo: {email}\r\n"
    message += "Subject: Argus SBOM Guard - Login Code\r\n\r\n"
    message += f"Your login code is: {code}\r\n\r\n"
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


async def create_api_key(
    db: AsyncSession, user_id: uuid.UUID, label: str = ""
) -> tuple[ApiKey, str]:
    raw, key_hash, prefix = generate_api_key()
    key = ApiKey(user_id=user_id, key_hash=key_hash, key_prefix=prefix, label=label)
    db.add(key)
    await db.flush()
    return key, raw


async def validate_api_key(db: AsyncSession, raw_key: str) -> User | None:
    if not raw_key.startswith("argus_"):
        return None

    key_hash = _hash_token(raw_key)
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == key_hash)
    )
    key = result.scalar_one_or_none()
    if not key:
        return None

    key.last_used_at = datetime.now(timezone.utc)
    return await get_user_by_id(db, key.user_id)


async def list_api_keys(db: AsyncSession) -> list[ApiKey]:
    result = await db.execute(
        select(ApiKey).order_by(ApiKey.created_at.desc())
    )
    return list(result.scalars().all())


async def revoke_api_key(db: AsyncSession, key_id: uuid.UUID) -> bool:
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id))
    key = result.scalar_one_or_none()
    if not key:
        return False
    await db.delete(key)
    await db.flush()
    return True
