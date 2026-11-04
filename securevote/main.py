from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from audit import get_client, log_event
from auth import decode_token
from config import IDS_EXEMPT_LOCALHOST
from database import get_db, init_db
from ids import check_rate_limit, is_ip_blocked, scan_input
from routes.auth_routes import router as auth_router
from routes.admin import router as admin_router
from routes.auditor import router as auditor_router
from routes.dashboards import router as dashboards_router
from routes.officer import router as officer_router
from routes.voter import router as voter_router

app = FastAPI(title="SecureVote", dependencies=[Depends(scan_input)])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount(
    "/static",
    StaticFiles(directory=str(Path(__file__).parent / "static")),
    name="static",
)
app.include_router(auth_router)
app.include_router(dashboards_router)
app.include_router(officer_router)
app.include_router(voter_router)
app.include_router(admin_router)
app.include_router(auditor_router)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    ip, user_agent = get_client(request)
    exempt_local = IDS_EXEMPT_LOCALHOST and ip == "127.0.0.1"

    if not exempt_local and is_ip_blocked(ip):
        log_event("HTTP_403", "WARN", None, None, ip, user_agent, "Blocked IP request")
        response = PlainTextResponse("Your IP is temporarily blocked", status_code=403)
    elif not exempt_local and check_rate_limit(ip):
        response = PlainTextResponse("Too many requests", status_code=429)
    else:
        connection = get_db()
        try:
            election = connection.execute(
                "SELECT integrity_status FROM election WHERE id = ?", (1,)
            ).fetchone()
            request.state.integrity_status = election["integrity_status"] if election else "UNKNOWN"
        finally:
            connection.close()
        response = await call_next(request)

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    messages = {
        401: "Authentication required.",
        403: "Access denied.",
        404: "Page not found.",
    }
    if exc.status_code in messages:
        if exc.status_code in {401, 403}:
            ip, user_agent = get_client(request)
            claims = decode_token(request.cookies.get("access_token", ""))
            log_event(
                f"HTTP_{exc.status_code}",
                "WARN",
                claims.get("sub") if claims else None,
                claims.get("role") if claims else None,
                ip,
                user_agent,
                request.url.path,
            )
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


@app.get("/", include_in_schema=False)
def home():
    return RedirectResponse(url="/login", status_code=303)


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