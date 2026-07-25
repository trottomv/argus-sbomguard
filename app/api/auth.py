from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from middleware import clear_session_cookie, set_session_cookie
from services.auth import (
    create_login_token,
    get_user_by_email,
    send_login_email,
    verify_login_token,
)
from templating import templates

router = APIRouter(tags=["auth"])


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"step": "email", "email": ""})


@router.post("/login", response_class=HTMLResponse)
async def login_request(
    request: Request,
    email: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    email = email.strip().lower()
    user = await get_user_by_email(db, email)

    # Only mint a login token for an existing user. We never fall back to the
    # admin account for an unknown address (that would let anyone request an
    # admin code), and we always render the same "code" step regardless of
    # whether the user exists, to avoid account enumeration.
    dev_code = None
    if user:
        code = await create_login_token(db, user.id)
        await db.commit()
        result = await send_login_email(email, code)
        # The raw code is only ever surfaced in the response in development,
        # when SMTP is not configured; never in other environments.
        if settings.app_env == "development" and isinstance(result, str):
            dev_code = result

    return templates.TemplateResponse(
        request,
        "login.html",
        {"step": "code", "email": email, "dev_code": dev_code},
    )


@router.post("/login/verify", response_class=HTMLResponse)
async def login_verify(
    request: Request,
    email: str = Form(...),
    code: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    email = email.strip().lower()
    code = code.strip().upper()
    user = await verify_login_token(db, code, email)
    await db.commit()

    if not user:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"step": "code", "email": email, "error": "Invalid or expired code"},
        )

    response = RedirectResponse(url="/", status_code=302)
    set_session_cookie(response, str(user.id), user.email)
    return response


@router.post("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/login", status_code=302)
    clear_session_cookie(response)
    return response
