from pathlib import Path

import bcrypt
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from auth import (
    DUMMY_PASSWORD_HASH,
    create_token,
    decode_token,
    decrypt_totp_secret,
    revoke,
    set_auth_cookie,
    verify_totp,
)
from database import get_db

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def _pre_2fa_user(request):
    token = request.cookies.get("access_token")
    claims = decode_token(token) if token else None
    if not claims or claims.get("stage") != "pre_2fa":
        return None, None

    connection = get_db()
    try:
        row = connection.execute(
            "SELECT id, student_id, name, role, totp_secret_enc FROM users WHERE id = ?",
            (claims["sub"],),
        ).fetchone()
    finally:
        connection.close()

    if row is None or row["role"] != claims.get("role"):
        return None, None
    return claims, dict(row)


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None},
    )


@router.post("/login")
def login(request: Request, student_id: str = Form(...), password: str = Form(...)):
    connection = get_db()
    try:
        row = connection.execute(
            "SELECT id, student_id, role, password_hash FROM users WHERE student_id = ?",
            (student_id,),
        ).fetchone()
    finally:
        connection.close()

    password_bytes = password.encode()
    too_long = len(password_bytes) > 72
    check_bytes = password_bytes[:72] if too_long else password_bytes
    candidate_hash = row["password_hash"].encode() if row is not None and not too_long else DUMMY_PASSWORD_HASH
    # Always do one bcrypt check so unknown student IDs do not get a cheaper response path.
    password_matches = bcrypt.checkpw(check_bytes, candidate_hash)

    if row is None or too_long or not password_matches:
        # PHASE 4 HOOK: log failed login / check account lockout here
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid credentials"},
            status_code=401,
        )

    token = create_token(row["id"], row["role"], "pre_2fa", 5)
    response = RedirectResponse(url="/verify-2fa", status_code=303)
    set_auth_cookie(response, token, max_age=5 * 60)
    return response


@router.get("/verify-2fa")
def verify_2fa_page(request: Request):
    claims, _ = _pre_2fa_user(request)
    if claims is None:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="verify_2fa.html",
        context={"error": None},
    )


@router.post("/verify-2fa")
def verify_2fa(request: Request, code: str = Form(...)):
    claims, user = _pre_2fa_user(request)
    if claims is None:
        return RedirectResponse(url="/login", status_code=303)

    try:
        secret = decrypt_totp_secret(user["totp_secret_enc"])
        code_is_valid = verify_totp(secret, code)
    except Exception:
        code_is_valid = False

    if not code_is_valid:
        # PHASE 4 HOOK: log failed second-factor verification here
        return templates.TemplateResponse(
            request=request,
            name="verify_2fa.html",
            context={"error": "Invalid code"},
            status_code=401,
        )

    revoke(claims["jti"])
    token = create_token(user["id"], user["role"], "full", 15)
    response = RedirectResponse(url="/dashboard", status_code=303)
    set_auth_cookie(response, token, max_age=15 * 60)
    return response


@router.post("/logout")
def logout(request: Request):
    token = request.cookies.get("access_token")
    claims = decode_token(token) if token else None
    if claims:
        revoke(claims["jti"])

    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="access_token", path="/", samesite="strict")
    return response