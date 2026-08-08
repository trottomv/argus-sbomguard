"""Regression tests for the passwordless login flow (issue: admin takeover)."""

from sqlalchemy import select

from config import settings
from models.user import LoginToken, User
from services.auth import create_login_token, verify_login_token


async def test_verify_login_token_is_bound_to_email(db_session):
    admin = User(email="admin@argus.local", is_admin=True)
    attacker = User(email="attacker@evil.com", is_admin=False)
    db_session.add_all([admin, attacker])
    await db_session.commit()

    code = await create_login_token(db_session, admin.id)
    await db_session.commit()

    # A token minted for the admin must not be redeemable against another email.
    assert await verify_login_token(db_session, code, "attacker@evil.com") is None

    # The token is still valid for its rightful owner.
    user = await verify_login_token(db_session, code, "admin@argus.local")
    assert user is not None
    assert user.id == admin.id


async def test_verify_login_token_is_single_use(db_session):
    admin = User(email="admin@argus.local", is_admin=True)
    db_session.add(admin)
    await db_session.commit()

    code = await create_login_token(db_session, admin.id)
    await db_session.commit()

    assert await verify_login_token(db_session, code, "admin@argus.local") is not None
    await db_session.commit()
    # Second attempt with the same code must fail (used flag).
    assert await verify_login_token(db_session, code, "admin@argus.local") is None


async def test_login_unknown_email_mints_no_token_and_leaks_no_code(client, db_session):
    # The `client` fixture seeds only admin@argus.local. An unknown address must
    # not mint an admin token nor surface a login code in the response.
    resp = await client.post("/login", data={"email": "ghost@nowhere.test"})
    assert resp.status_code == 200
    assert "Login code:" not in resp.text

    tokens = (await db_session.execute(select(LoginToken))).scalars().all()
    assert tokens == []


async def test_login_existing_user_hides_code_by_default(client):
    # The `client` fixture seeds admin@argus.local. With the default
    # configuration the one-time code must NOT be rendered in the response.
    resp = await client.post("/login", data={"email": "admin@argus.local"})
    assert resp.status_code == 200
    assert "Login code:" not in resp.text


async def test_login_existing_user_shows_code_when_enabled(client, monkeypatch):
    # Explicitly enabling SHOW_LOGIN_CODE_IN_RESPONSE (e.g. APP_ENV=demo without
    # SMTP) surfaces the one-time code in the login page response. smtp_host is
    # forced empty so send_login_email short-circuits and returns the code.
    monkeypatch.setattr(settings, "show_login_code_in_response", True)
    monkeypatch.setattr(settings, "smtp_host", "")
    resp = await client.post("/login", data={"email": "admin@argus.local"})
    assert resp.status_code == 200
    assert "Login code:" in resp.text
