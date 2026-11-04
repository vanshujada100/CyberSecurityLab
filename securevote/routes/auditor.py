from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates

from audit import get_client, log_event
from database import get_db
from hashchain import verify_audit_chain, verify_ballot_chain, verify_ballot_count
from ids import raise_alert
from rbac import require_role

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def _integrity_checks(connection):
    return {
        "Ballot hash chain": verify_ballot_chain(connection),
        "Audit hash chain": verify_audit_chain(connection),
        "Ballot count": verify_ballot_count(connection),
    }


def _audit_context(request, user, event_type, details):
    ip, user_agent = get_client(request)
    log_event(event_type, "INFO", str(user["id"]), user["role"], ip, user_agent, details)


@router.get("/auditor/logs")
def auditor_logs(
    request: Request,
    actor_id: str = None,
    ip: str = None,
    event_type: str = None,
    severity: str = None,
    date_from: str = None,
    date_to: str = None,
    user=Depends(require_role("auditor")),
):
    conditions = []
    parameters = []
    for value, fragment in (
        (actor_id, "actor_id = ?"),
        (ip, "ip = ?"),
        (event_type, "event_type = ?"),
        (severity, "severity = ?"),
        (date_from, "date(ts) >= date(?)"),
        (date_to, "date(ts) <= date(?)"),
    ):
        if value:
            conditions.append(fragment)
            parameters.append(value)

    query = "SELECT id, ts, event_type, severity, actor_id, role, ip, user_agent, details, prev_hash, hash FROM audit_log"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    parameters.append(200)

    connection = get_db()
    try:
        logs = [dict(row) for row in connection.execute(query, parameters).fetchall()]
    finally:
        connection.close()

    _audit_context(request, user, "AUDIT_VIEWED", "Audit log viewed")
    return templates.TemplateResponse(
        request=request,
        name="auditor_logs.html",
        context={
            "logs": logs,
            "filters": {
                "actor_id": actor_id or "",
                "ip": ip or "",
                "event_type": event_type or "",
                "severity": severity or "",
                "date_from": date_from or "",
                "date_to": date_to or "",
            },
        },
    )


@router.get("/auditor/verify")
def verify_integrity(request: Request, user=Depends(require_role("auditor"))):
    connection = get_db()
    try:
        checks = _integrity_checks(connection)
    finally:
        connection.close()

    failed = any(not result["ok"] for result in checks.values())
    ip, user_agent = get_client(request)
    if failed:
        connection = get_db()
        try:
            connection.execute(
                "UPDATE election SET integrity_status = ? WHERE id = ?",
                ("COMPROMISED", 1),
            )
            connection.commit()
        finally:
            connection.close()
        request.state.integrity_status = "COMPROMISED"
        raise_alert(
            "INTEGRITY_VIOLATION",
            "CRITICAL",
            ip,
            user["id"],
            "One or more forensic integrity checks failed",
        )
    else:
        log_event(
            "INTEGRITY_VERIFIED",
            "INFO",
            str(user["id"]),
            user["role"],
            ip,
            user_agent,
            "All integrity checks passed",
        )

    connection = get_db()
    try:
        election = connection.execute(
            "SELECT integrity_status FROM election WHERE id = ?", (1,)
        ).fetchone()
        integrity_status = election["integrity_status"] if election else "UNKNOWN"
    finally:
        connection.close()

    display_checks = []
    for name, result in checks.items():
        reason = result.get("reason")
        if name == "Ballot count":
            reason = "ballot and voter-status counts match" if result["ok"] else "ballot and voter-status counts differ"
        display_checks.append(
            {
                "name": name,
                "ok": result["ok"],
                "checked": result.get("checked"),
                "broken_at": result.get("broken_at"),
                "reason": reason,
                "ballots": result.get("ballots"),
                "voted": result.get("voted"),
            }
        )

    return templates.TemplateResponse(
        request=request,
        name="verify.html",
        context={"checks": display_checks, "integrity_status": integrity_status},
    )


@router.get("/auditor/report")
def forensic_report(request: Request, user=Depends(require_role("auditor"))):
    generated_at = datetime.now(timezone.utc).isoformat()
    now = generated_at
    connection = get_db()
    try:
        election = connection.execute(
            "SELECT state, integrity_status FROM election WHERE id = ?", (1,)
        ).fetchone()
        checks = _integrity_checks(connection)
        alert_counts = [
            dict(row)
            for row in connection.execute(
                """SELECT rule, COUNT(*) AS total FROM ids_alerts
                   GROUP BY rule ORDER BY total DESC, rule"""
            ).fetchall()
        ]
        top_sources = [
            dict(row)
            for row in connection.execute(
                """SELECT ip, SUM(event_count) AS total FROM (
                       SELECT ip, COUNT(*) AS event_count FROM ids_alerts
                       WHERE ip IS NOT NULL GROUP BY ip
                       UNION ALL
                       SELECT ip, COUNT(*) AS event_count FROM audit_log
                       WHERE event_type IN (?, ?) AND ip IS NOT NULL GROUP BY ip
                   ) AS source_events
                   GROUP BY ip ORDER BY total DESC, ip LIMIT ?""",
                ("LOGIN_FAILED", "TWO_FACTOR_FAILED", 5),
            ).fetchall()
        ]
        locked_users = [
            dict(row)
            for row in connection.execute(
                """SELECT id, student_id, role, failed_attempts, locked_until
                   FROM users WHERE locked_until > ? ORDER BY locked_until DESC""",
                (now,),
            ).fetchall()
        ]
        blocked_ips = [
            dict(row)
            for row in connection.execute(
                """SELECT ip, reason, blocked_until FROM blocked_ips
                   WHERE blocked_until > ? ORDER BY blocked_until DESC""",
                (now,),
            ).fetchall()
        ]
        high_events = [
            dict(row)
            for row in connection.execute(
                """SELECT id, ts, event_type, severity, actor_id, role, ip, details
                   FROM audit_log WHERE severity IN (?, ?)
                   ORDER BY id ASC""",
                ("HIGH", "CRITICAL"),
            ).fetchall()
        ]
    finally:
        connection.close()

    _audit_context(request, user, "REPORT_GENERATED", "Forensic report generated")
    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "generated_at": generated_at,
            "election_state": election["state"] if election else "UNKNOWN",
            "integrity_status": election["integrity_status"] if election else "UNKNOWN",
            "checks": checks,
            "alert_counts": alert_counts,
            "top_sources": top_sources,
            "locked_users": locked_users,
            "blocked_ips": blocked_ips,
            "high_events": high_events,
            "window_start": window_start,
        },
    )