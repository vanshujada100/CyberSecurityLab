from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from database import get_db, init_db
from routes.auth_routes import router as auth_router
from routes.dashboards import router as dashboards_router

app = FastAPI(title="SecureVote")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.include_router(auth_router)
app.include_router(dashboards_router)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    messages = {
        401: "Authentication required.",
        403: "Access denied.",
        404: "Page not found.",
    }
    if exc.status_code in messages:
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={"status_code": exc.status_code, "message": messages[exc.status_code]},
            status_code=exc.status_code,
        )
    return await http_exception_handler(request, exc)


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