"""Regression tests for API key expiration enforcement."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from middleware.api_key import api_key_required
from models.auth import ApiKey, User
from services.auth import (
    create_api_key,
    generate_api_key,
    list_api_keys,
    revoke_api_key,
    seed_admin_user,
    validate_api_key,
)


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


def _make_request(*, session_user=None, api_key: str = ""):
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/test",
        "query_string": b"",
        "headers": [(b"x-api-key", api_key.encode())] if api_key else [],
        "state": {},
    }
    if session_user is not None:
        scope["state"]["user"] = session_user
    return Request(scope)


async def test_api_key_required_returns_session_user(db_session):
    user = await _make_user(db_session, "session@example.com")
    request = _make_request(session_user=user)
    got = await api_key_required(request, db=db_session)
    assert got == user


async def test_api_key_required_missing_header_raises_401(db_session):
    request = _make_request()
    with pytest.raises(HTTPException) as exc:
        await api_key_required(request, db=db_session)
    assert exc.value.status_code == 401
    assert exc.value.detail == "API key required"


async def test_api_key_required_invalid_key_raises_401(db_session):
    request = _make_request(api_key="argus_not-a-real-key")
    with pytest.raises(HTTPException) as exc:
        await api_key_required(request, db=db_session)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid API key"


async def test_api_key_required_valid_header(db_session):
    user = await _make_user(db_session, "header@example.com")
    _key, raw = await create_api_key(db_session, user.id)
    await db_session.commit()

    request = _make_request(api_key=raw)
    got = await api_key_required(request, db=db_session)
    assert got.id == user.id


async def test_validate_api_key_rejects_wrong_prefix(db_session):
    assert await validate_api_key(db_session, "bearer_whatever") is None


async def test_validate_api_key_rejects_unknown_hash(db_session):
    user = await _make_user(db_session, "unknown@example.com")
    _raw, key_hash, prefix = generate_api_key()
    db_session.add(
        ApiKey(user_id=user.id, key_hash=key_hash, key_prefix=prefix),
    )
    await db_session.commit()

    other_raw, _other_hash, _other_prefix = generate_api_key()
    assert await validate_api_key(db_session, other_raw) is None


async def test_validate_api_key_updates_last_used_at(db_session):
    user = await _make_user(db_session, "lastused@example.com")
    api_key_obj, raw = await create_api_key(db_session, user.id)
    await db_session.commit()

    before = datetime.now(UTC)
    await validate_api_key(db_session, raw)
    key = (
        await db_session.execute(select(ApiKey).where(ApiKey.key_hash == api_key_obj.key_hash))
    ).scalar_one()
    assert key.last_used_at is not None
    assert key.last_used_at >= before


async def test_validate_api_key_naive_expiry_interpreted_as_utc(db_session):
    user = await _make_user(db_session, "naive@example.com")
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

    key = (await db_session.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))).scalar_one()
    key.expires_at = key.expires_at.replace(tzinfo=None)
    await db_session.commit()

    got = await validate_api_key(db_session, raw)
    assert got is not None
    assert got.id == user.id


async def test_list_api_keys_orders_by_created_desc(db_session):
    user = await _make_user(db_session, "listkeys@example.com")

    _k1, _raw1 = await create_api_key(db_session, user.id, label="first")
    _k2, _raw2 = await create_api_key(db_session, user.id, label="second")
    await db_session.commit()

    keys = await list_api_keys(db_session)
    assert len(keys) == 2
    assert {key.label for key in keys} == {"first", "second"}


async def test_revoke_api_key_found_and_missing(db_session):
    user = await _make_user(db_session, "revoke@example.com")
    key, _raw = await create_api_key(db_session, user.id, label="to-revoke")
    await db_session.commit()

    assert await revoke_api_key(db_session, key.id) is True
    await db_session.commit()

    missing = await revoke_api_key(db_session, uuid.uuid4())
    assert missing is False


async def test_seed_admin_user_creates_when_missing(db_session):
    user = await seed_admin_user(db_session)
    assert user.email == "admin@argus.local"
    assert user.is_admin is True


async def test_seed_admin_user_reuses_existing(db_session):
    db_session.add(User(email="admin@argus.local", is_admin=False))
    await db_session.commit()

    user = await seed_admin_user(db_session)
    assert user.is_admin is False
    assert (await db_session.execute(select(User))).scalars().all().__len__() == 1
