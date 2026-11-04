from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from audit import get_client, log_event
from database import get_db
from rbac import require_role

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/officer/panel")
def officer_panel(request: Request, user=Depends(require_role("officer"))):
    connection = get_db()
    try:
        election = connection.execute(
            "SELECT state FROM election WHERE id = ?", (1,)
        ).fetchone()
        voted = connection.execute(
            "SELECT COUNT(*) FROM voter_status WHERE has_voted = ?", (1,)
        ).fetchone()[0]
        total = connection.execute(
            "SELECT COUNT(*) FROM users WHERE role = ?", ("voter",)
        ).fetchone()[0]
        candidates = [
            dict(row)
            for row in connection.execute(
                "SELECT id, name, position, description FROM candidates ORDER BY id"
            ).fetchall()
        ]
    finally:
        connection.close()

    return templates.TemplateResponse(
        request=request,
        name="officer.html",
        context={
            "state": election["state"] if election else "NOT_STARTED",
            "voted": voted,
            "total": total,
            "candidates": candidates,
        },
    )


@router.post("/officer/candidates")
def add_candidate(
    request: Request,
    name: str = Form(...),
    position: str = Form(...),
    description: str = Form(""),
    user=Depends(require_role("officer")),
):
    connection = get_db()
    added = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        election = connection.execute(
            "SELECT state FROM election WHERE id = ?", (1,)
        ).fetchone()
        if election and election["state"] == "NOT_STARTED":
            connection.execute(
                "INSERT INTO candidates (name, position, description) VALUES (?, ?, ?)",
                (name, position, description),
            )
            connection.commit()
            added = True
        else:
            connection.rollback()
    finally:
        connection.close()

    ip, user_agent = get_client(request)
    if not added:
        log_event("CANDIDATE_ADD_REJECTED", "WARN", str(user["id"]), user["role"], ip, user_agent, "Election already started")
        raise HTTPException(status_code=403, detail="Candidates cannot be changed after the election starts.")
    log_event("CANDIDATE_ADDED", "INFO", str(user["id"]), user["role"], ip, user_agent, name)
    return RedirectResponse(url="/officer/panel", status_code=303)


def _transition_election(request, user, expected_state, new_state):
    timestamp = datetime.now(timezone.utc).isoformat()
    connection = get_db()
    transitioned = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        election = connection.execute(
            "SELECT state FROM election WHERE id = ?", (1,)
        ).fetchone()
        if election and election["state"] == expected_state:
            if new_state == "OPEN":
                connection.execute(
                    "UPDATE election SET state = ?, opened_at = ? WHERE id = ?",
                    (new_state, timestamp, 1),
                )
            else:
                connection.execute(
                    "UPDATE election SET state = ?, closed_at = ? WHERE id = ?",
                    (new_state, timestamp, 1),
                )
            connection.commit()
            transitioned = True
        else:
            connection.rollback()
    finally:
        connection.close()

    ip, user_agent = get_client(request)
    if not transitioned:
        log_event(
            "ELECTION_TRANSITION_REJECTED",
            "WARN",
            str(user["id"]),
            user["role"],
            ip,
            user_agent,
            f"{expected_state} to {new_state}",
        )
        raise HTTPException(status_code=400, detail="Election state transition is not allowed.")

    event_type = "ELECTION_OPENED" if new_state == "OPEN" else "ELECTION_CLOSED"
    log_event(event_type, "INFO", str(user["id"]), user["role"], ip, user_agent, new_state)
    return RedirectResponse(url="/officer/panel", status_code=303)


@router.post("/officer/election/open")
def open_election(request: Request, user=Depends(require_role("officer"))):
    return _transition_election(request, user, "NOT_STARTED", "OPEN")


@router.post("/officer/election/close")
def close_election(request: Request, user=Depends(require_role("officer"))):
    return _transition_election(request, user, "OPEN", "CLOSED")