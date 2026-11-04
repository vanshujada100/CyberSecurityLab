from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from database import get_db, init_db

app = FastAPI(title="SecureVote")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    connection = get_db()
    try:
        election = connection.execute(
            "SELECT state FROM election WHERE id = ?", (1,)
        ).fetchone()
        return {
            "status": "ok",
            "election_state": election["state"] if election else None,
        }
    finally:
        connection.close()