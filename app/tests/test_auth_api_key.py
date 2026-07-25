"""Regression tests for API key expiration enforcement."""

from datetime import UTC, datetime, timedelta

from models.user import ApiKey, User
from services.auth import create_api_key, generate_api_key, validate_api_key


async def _make_user(db_session, email: str) -> User:
    user = User(email=email, is_admin=False)
    db_session.add(user)
    await db_session.commit()
    return user


async def test_validate_api_key_rejects_expired(db_session):
    user = await _make_user(db_session, "expired@example.com")
    raw, key_hash, prefix = generate_api_key()
    db_session.add(
        ApiKey(
            user_id=user.id,
            key_hash=key_hash,
            key_prefix=prefix,
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
    )
    await db_session.commit()

    assert await validate_api_key(db_session, raw) is None


async def test_validate_api_key_accepts_future_expiry(db_session):
    user = await _make_user(db_session, "future@example.com")
    raw, key_hash, prefix = generate_api_key()
    db_session.add(
        ApiKey(
            user_id=user.id,
            key_hash=key_hash,
            key_prefix=prefix,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    await db_session.commit()

    got = await validate_api_key(db_session, raw)
    assert got is not None
    assert got.id == user.id


async def test_validate_api_key_accepts_no_expiry(db_session):
    user = await _make_user(db_session, "noexpiry@example.com")
    _key, raw = await create_api_key(db_session, user.id)
    await db_session.commit()

    got = await validate_api_key(db_session, raw)
    assert got is not None
    assert got.id == user.id
