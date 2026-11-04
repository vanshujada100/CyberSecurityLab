from datetime import datetime, timedelta, timezone
import re
import uuid

import bcrypt
from cryptography.fernet import Fernet
import jwt
import pyotp

from config import FERNET_KEY, SECRET_KEY

# One fixed dummy hash keeps unknown-user login checks on the bcrypt path too.
DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"SecureVote-dummy-password", bcrypt.gensalt())
REVOKED_JTIS = set()


def hash_password(plain):
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain, hashed):
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def validate_password_policy(plain):
    if len(plain) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isupper() for char in plain):
        return False, "Password must include an uppercase letter."
    if not any(char.islower() for char in plain):
        return False, "Password must include a lowercase letter."
    if not any(char.isdigit() for char in plain):
        return False, "Password must include a digit."
    if not any(not char.isalnum() and not char.isspace() for char in plain):
        return False, "Password must include a symbol."
    return True, "Password meets the policy."


def decrypt_totp_secret(enc):
    return Fernet(FERNET_KEY.encode()).decrypt(enc.encode()).decode()


def verify_totp(secret, code):
    if not isinstance(code, str) or re.fullmatch(r"[0-9]{6}", code) is None:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def create_token(user_id, role, stage, minutes):
    if stage not in {"pre_2fa", "full"}:
        raise ValueError("Invalid token stage.")
    expected_minutes = 5 if stage == "pre_2fa" else 15
    if minutes != expected_minutes:
        raise ValueError("Token lifetime does not match its authentication stage.")

    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user_id),
        "role": role,
        "stage": stage,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(claims, SECRET_KEY, algorithm="HS256")


def decode_token(token):
    try:
        claims = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],
            options={"require": ["sub", "role", "stage", "jti", "iat", "exp"]},
        )
        if claims["stage"] not in {"pre_2fa", "full"}:
            return None
        if claims["jti"] in REVOKED_JTIS:
            return None
        return claims
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        return None


def revoke(jti):
    # In-memory revocation is a demo simplification; production needs a DB or Redis.
    REVOKED_JTIS.add(jti)


def set_auth_cookie(response, token, max_age):
    from config import COOKIE_SECURE

    response.set_cookie(
        key="access_token",
        value=token,
        max_age=max_age,
        httponly=True,
        samesite="strict",
        secure=COOKIE_SECURE,
        path="/",
    )