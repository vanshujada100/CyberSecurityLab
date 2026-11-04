from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from audit import get_client, log_event
from crypto_utils import decrypt_ballot
from database import get_db
from rbac import require_role

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/admin/results")
def results(request: Request, user=Depends(require_role("admin"))):
    connection = get_db()
    try:
        election = connection.execute(
            "SELECT state FROM election WHERE id = ?", (1,)
        ).fetchone()
        if election is None or election["state"] != "CLOSED":
            connection.close()
            ip, user_agent = get_client(request)
            log_event(
                "RESULTS_DENIED",
                "WARN",
                str(user["id"]),
                user["role"],
                ip,
                user_agent,
                "Election is not closed",
            )
            raise HTTPException(status_code=403, detail="Results are available after the election closes.")

        counts = {}
        candidates = connection.execute(
            "SELECT id, name, position FROM candidates ORDER BY position, name"
        ).fetchall()
        for candidate in candidates:
            counts[candidate["id"]] = 0
        ballots = connection.execute("SELECT ciphertext FROM ballots").fetchall()
        for ballot in ballots:
            candidate_id = decrypt_ballot(ballot["ciphertext"])
            if candidate_id in counts:
                counts[candidate_id] += 1
        tally = [
            {"name": candidate["name"], "position": candidate["position"], "votes": counts[candidate["id"]]}
            for candidate in candidates
        ]
    finally:
        connection.close()

    ip, user_agent = get_client(request)
    log_event("RESULTS_VIEWED", "INFO", str(user["id"]), user["role"], ip, user_agent, "Closed election tally")
    return templates.TemplateResponse(
        request=request,
        name="results.html",
        context={"tally": tally},
    )


@router.get("/admin/alerts")
def alerts(request: Request, user=Depends(require_role("admin"))):
    connection = get_db()
    try:
        rows = [
            dict(row)
            for row in connection.execute(
                """SELECT ts, rule, severity, ip, user_id, details, status
                   FROM ids_alerts ORDER BY id DESC"""
            ).fetchall()
        ]
    finally:
        connection.close()
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={"alerts": rows},
    )


@router.get("/admin/blocked")
def blocked(request: Request, user=Depends(require_role("admin"))):
    now = datetime.now(timezone.utc).isoformat()
    connection = get_db()
    try:
        ips = [
            dict(row)
            for row in connection.execute(
                """SELECT ip, reason, blocked_until FROM blocked_ips
                   WHERE blocked_until > ? ORDER BY blocked_until DESC""",
                (now,),
            ).fetchall()
        ]
        users = [
            dict(row)
            for row in connection.execute(
                """SELECT id, student_id, role, failed_attempts, locked_until
                   FROM users WHERE locked_until > ? ORDER BY locked_until DESC""",
                (now,),
            ).fetchall()
        ]
    finally:
        connection.close()
    return templates.TemplateResponse(
        request=request,
        name="blocked.html",
        context={"ips": ips, "users": users},
    )


@router.post("/admin/unblock-ip")
def unblock_ip(request: Request, ip: str = Form(...), user=Depends(require_role("admin"))):
    connection = get_db()
    try:
        connection.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        connection.commit()
    finally:
        connection.close()
    client_ip, user_agent = get_client(request)
    log_event("ADMIN_IP_UNBLOCKED", "INFO", str(user["id"]), user["role"], client_ip, user_agent, ip)
    return RedirectResponse(url="/admin/blocked", status_code=303)


@router.post("/admin/unlock-user")
def unlock_user(
    request: Request,
    user_id: int = Form(...),
    admin=Depends(require_role("admin")),
):
    connection = get_db()
    try:
        connection.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )
        connection.commit()
    finally:
        connection.close()
    client_ip, user_agent = get_client(request)
    log_event(
        "ADMIN_USER_UNLOCKED",
        "INFO",
        str(admin["id"]),
        admin["role"],
        client_ip,
        user_agent,
        str(user_id),
    )
    return RedirectResponse(url="/admin/blocked", status_code=303)