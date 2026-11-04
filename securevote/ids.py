from datetime import datetime, timedelta, timezone
import re
import threading
import time

from fastapi import HTTPException, Request

from audit import get_client, log_event
from auth import decode_token, revoke
from database import get_db

FAILED_AUTH_LIMIT = 5
FAILED_AUTH_WINDOW_MINUTES = 10
ACCOUNT_LOCK_MINUTES = 15
PRIVILEGE_LIMIT = 3
PRIVILEGE_WINDOW_MINUTES = 5
REQUEST_LIMIT = 60
REQUEST_WINDOW_SECONDS = 60
RATE_BLOCK_MINUTES = 5
INJECTION_BLOCK_HITS = 3
INJECTION_BLOCK_MINUTES = 10

_counter_lock = threading.Lock()
_request_counts = {}
_injection_counts = {}

_SIGNATURES = [
    re.compile(r"(?i)'\s*or\b|union\s+select|--|;\s*drop\b|1\s*=\s*1"),
    re.compile(r"(?i)<\s*script|onerror\s*=|javascript\s*:"),
    re.compile(r"\.\./"),
]


def utc_now():
    return datetime.now(timezone.utc)


def is_user_locked(locked_until):
    if not locked_until:
        return False
    expiration = datetime.fromisoformat(locked_until.replace("Z", "+00:00"))
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=timezone.utc)
    return expiration > utc_now()


def reset_failed_attempts(user_id):
    connection = get_db()
    try:
        connection.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )
        connection.commit()
    finally:
        connection.close()


def raise_alert(rule, severity, ip, user_id, details):
    timestamp = utc_now().isoformat()
    actor_id = str(user_id) if user_id is not None else None
    connection = get_db()
    try:
        connection.execute(
            """INSERT INTO ids_alerts (ts, rule, severity, ip, user_id, details)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (timestamp, rule, severity, ip, actor_id, details),
        )
        connection.commit()
    finally:
        connection.close()

    log_event("IDS_ALERT", severity, actor_id, None, ip, None, f"{rule}: {details}")


def record_auth_failure(event_type, user_id, role, ip, user_agent, details):
    actor_id = str(user_id) if user_id is not None else None
    log_event(event_type, "WARN", actor_id, role, ip, user_agent, details)
    if user_id is None:
        return False

    now = utc_now()
    window_start = (now - timedelta(minutes=FAILED_AUTH_WINDOW_MINUTES)).isoformat()
    lock_until = (now + timedelta(minutes=ACCOUNT_LOCK_MINUTES)).isoformat()
    should_alert = False
    locked = False
    connection = get_db()
    try:
        connection.execute("BEGIN IMMEDIATE")
        count = connection.execute(
            """SELECT COUNT(*) FROM audit_log
               WHERE actor_id = ? AND event_type IN (?, ?) AND ts >= ?""",
            (actor_id, "LOGIN_FAILED", "TWO_FACTOR_FAILED", window_start),
        ).fetchone()[0]
        row = connection.execute(
            "SELECT locked_until FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        locked = row is not None and is_user_locked(row["locked_until"])
        if row is not None:
            if count >= FAILED_AUTH_LIMIT and not locked:
                connection.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (count, lock_until, user_id),
                )
                should_alert = True
                locked = True
            else:
                connection.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?",
                    (count, user_id),
                )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    if should_alert:
        raise_alert(
            "BRUTE_FORCE_LOCKOUT",
            "HIGH",
            ip,
            user_id,
            f"{count} failed authentication attempts within {FAILED_AUTH_WINDOW_MINUTES} minutes",
        )
    return locked


def record_privilege_violation(request, user):
    ip, user_agent = get_client(request)
    actor_id = str(user["id"])
    log_event(
        "PRIVILEGE_VIOLATION",
        "WARN",
        actor_id,
        user["role"],
        ip,
        user_agent,
        request.url.path,
    )
    window_start = (utc_now() - timedelta(minutes=PRIVILEGE_WINDOW_MINUTES)).isoformat()
    connection = get_db()
    try:
        count = connection.execute(
            """SELECT COUNT(*) FROM audit_log
               WHERE actor_id = ? AND event_type = ? AND ts >= ?""",
            (actor_id, "PRIVILEGE_VIOLATION", window_start),
        ).fetchone()[0]
    finally:
        connection.close()

    if count >= PRIVILEGE_LIMIT:
        claims = decode_token(request.cookies.get("access_token", ""))
        if claims:
            revoke(claims["jti"])
        raise_alert(
            "PRIVILEGE_PROBING",
            "HIGH",
            ip,
            user["id"],
            f"{count} role violations within {PRIVILEGE_WINDOW_MINUTES} minutes",
        )


def is_ip_blocked(ip):
    connection = get_db()
    try:
        row = connection.execute(
            "SELECT blocked_until FROM blocked_ips WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return False
        if is_user_locked(row["blocked_until"]):
            return True
        connection.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        connection.commit()
        return False
    finally:
        connection.close()


def block_ip(ip, reason, minutes):
    blocked_until = (utc_now() + timedelta(minutes=minutes)).isoformat()
    connection = get_db()
    try:
        connection.execute(
            """INSERT INTO blocked_ips (ip, reason, blocked_until)
               VALUES (?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                   reason = excluded.reason, blocked_until = excluded.blocked_until""",
            (ip, reason, blocked_until),
        )
        connection.commit()
    finally:
        connection.close()


def check_rate_limit(ip):
    now = time.monotonic()
    over_limit = False
    with _counter_lock:
        window_start, count = _request_counts.get(ip, (now, 0))
        if now - window_start >= REQUEST_WINDOW_SECONDS:
            window_start, count = now, 0
        count += 1
        _request_counts[ip] = (window_start, count)
        over_limit = count > REQUEST_LIMIT

    if over_limit:
        block_ip(ip, "REQUEST_RATE", RATE_BLOCK_MINUTES)
        raise_alert(
            "REQUEST_RATE_LIMIT",
            "HIGH",
            ip,
            None,
            f"More than {REQUEST_LIMIT} requests in {REQUEST_WINDOW_SECONDS} seconds",
        )
    return over_limit


async def scan_input(request: Request):
    values = [value for _, value in request.query_params.multi_items()]
    form = await request.form()
    values.extend(value for _, value in form.multi_items())
    matched = any(signature.search(str(value)) for value in values for signature in _SIGNATURES)
    if not matched:
        return

    ip, user_agent = get_client(request)
    claims = decode_token(request.cookies.get("access_token", ""))
    user_id = claims.get("sub") if claims else None
    details = f"Input signature detected on {request.url.path}"
    raise_alert("INJECTION_SIGNATURE", "HIGH", ip, user_id, details)

    with _counter_lock:
        hits = _injection_counts.get(ip, 0) + 1
        _injection_counts[ip] = hits
    if hits >= INJECTION_BLOCK_HITS:
        block_ip(ip, "INJECTION_SIGNATURE", INJECTION_BLOCK_MINUTES)
        with _counter_lock:
            _injection_counts[ip] = 0
        raise_alert(
            "INJECTION_IP_BLOCK",
            "HIGH",
            ip,
            user_id,
            f"{INJECTION_BLOCK_HITS} injection signatures; blocked for {INJECTION_BLOCK_MINUTES} minutes",
        )
    raise HTTPException(status_code=400, detail="Request blocked")