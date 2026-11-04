import hashlib
from pathlib import Path
import secrets
import uuid

from fastapi import APIRouter, Depends, Form, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from audit import get_client, log_event
from crypto_utils import encrypt_ballot
from database import get_db
from hashchain import compute_hash, get_last_ballot_hash
from ids import raise_alert
from rbac import require_role

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/vote", response_class=HTMLResponse)
def vote_page(request: Request, user=Depends(require_role("voter"))):
    connection = get_db()
    try:
        election = connection.execute(
            "SELECT state FROM election WHERE id = ?", (1,)
        ).fetchone()
        status = connection.execute(
            "SELECT has_voted FROM voter_status WHERE user_id = ?", (user["id"],)
        ).fetchone()
        state = election["state"] if election else None
        has_voted = bool(status["has_voted"]) if status else False
        candidates = []
        if state == "OPEN":
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
        name="ballot.html",
        context={"state": state, "has_voted": has_voted, "candidates": candidates},
    )


@router.post("/vote")
def cast_vote(
    request: Request,
    candidate_id: int = Form(...),
    user=Depends(require_role("voter")),
):
    ip, user_agent = get_client(request)
    connection = get_db()
    rejection = None
    receipt = None
    try:
        # A write lock makes eligibility and the one-vote update atomic across requests.
        connection.execute("BEGIN IMMEDIATE")
        election = connection.execute(
            "SELECT state FROM election WHERE id = ?", (1,)
        ).fetchone()
        if election is None or election["state"] != "OPEN":
            connection.rollback()
            rejection = "out_of_window"
        else:
            candidate = connection.execute(
                "SELECT id FROM candidates WHERE id = ?", (candidate_id,)
            ).fetchone()
            if candidate is None:
                connection.rollback()
                rejection = "invalid_candidate"
            else:
                updated = connection.execute(
                    """UPDATE voter_status SET has_voted = 1
                       WHERE user_id = ? AND has_voted = 0""",
                    (user["id"],),
                )
                if updated.rowcount == 0:
                    connection.rollback()
                    rejection = "double_vote"
                else:
                    ciphertext = encrypt_ballot(candidate_id)
                    receipt = secrets.token_hex(8)
                    receipt_hash = hashlib.sha256(receipt.encode()).hexdigest()
                    ballot_id = str(uuid.uuid4())
                    previous_hash = get_last_ballot_hash(connection)
                    ballot_hash = compute_hash(previous_hash, ciphertext, ballot_id)
                    connection.execute(
                        """INSERT INTO ballots
                           (id, ciphertext, receipt_hash, prev_hash, hash)
                           VALUES (?, ?, ?, ?, ?)""",
                        (ballot_id, ciphertext, receipt_hash, previous_hash, ballot_hash),
                    )
                    connection.commit()
    finally:
        connection.close()

    actor_id = str(user["id"])
    if rejection:
        log_event("VOTE_REJECTED", "WARN", actor_id, user["role"], ip, user_agent, rejection)
        if rejection == "out_of_window":
            raise_alert("OUT_OF_WINDOW_VOTE", "MEDIUM", ip, user["id"], "Vote attempted while election was not open")
            raise HTTPException(status_code=403, detail="Voting is not open.")
        if rejection == "double_vote":
            raise_alert("DOUBLE_VOTE", "HIGH", ip, user["id"], "Repeated vote submission")
            raise HTTPException(status_code=409, detail="Vote already recorded.")
        raise HTTPException(status_code=400, detail="Invalid candidate.")

    log_event("VOTE_CAST", "INFO", actor_id, user["role"], ip, user_agent, "Encrypted ballot accepted")
    return templates.TemplateResponse(
        request=request,
        name="receipt.html",
        context={"receipt": receipt, "found": None},
    )


@router.post("/verify-receipt", response_class=HTMLResponse)
def verify_receipt(
    request: Request,
    receipt: str = Form(...),
    user=Depends(require_role("voter")),
):
    receipt_hash = hashlib.sha256(receipt.encode()).hexdigest()
    connection = get_db()
    try:
        row = connection.execute(
            "SELECT 1 FROM ballots WHERE receipt_hash = ?", (receipt_hash,)
        ).fetchone()
    finally:
        connection.close()

    return templates.TemplateResponse(
        request=request,
        name="receipt.html",
        context={"receipt": None, "found": row is not None},
    )