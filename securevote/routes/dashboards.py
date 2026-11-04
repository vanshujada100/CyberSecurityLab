from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from rbac import get_current_user, require_role

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

ROLE_DASHBOARDS = {
    "voter": "/voter/dashboard",
    "officer": "/officer/dashboard",
    "admin": "/admin/dashboard",
    "auditor": "/auditor/dashboard",
}


@router.get("/dashboard")
def dashboard(user=Depends(get_current_user)):
    destination = ROLE_DASHBOARDS.get(user["role"])
    if destination is None:
        raise HTTPException(status_code=403, detail="Access denied.")
    return RedirectResponse(url=destination, status_code=303)


def _render_dashboard(request, user, capabilities):
    links_by_role = {
        "voter": [("Vote", "/vote")],
        "officer": [("Officer panel", "/officer/panel")],
        "admin": [
            ("Users", "/admin/users"),
            ("Results", "/admin/results"),
            ("Alerts", "/admin/alerts"),
            ("Blocked IPs and locked users", "/admin/blocked"),
        ],
        "auditor": [
            ("Audit logs", "/auditor/logs"),
            ("Verify integrity", "/auditor/verify"),
            ("Forensic report", "/auditor/report"),
            ("Election tally", "/auditor/results"),
        ],
    }
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": user,
            "capabilities": capabilities,
            "dashboard_links": links_by_role.get(user["role"], []),
        },
    )


@router.get("/voter/dashboard")
def voter_dashboard(request: Request, user=Depends(require_role("voter"))):
    return _render_dashboard(
        request,
        user,
        [
            "Review candidates and cast one vote while the election is open.",
            "Check whether your receipt is included without revealing your choice.",
        ],
    )


@router.get("/officer/dashboard")
def officer_dashboard(request: Request, user=Depends(require_role("officer"))):
    return _render_dashboard(
        request,
        user,
        [
            "Add candidates before opening the poll.",
            "Open or close the election and monitor turnout without seeing results.",
        ],
    )


@router.get("/admin/dashboard")
def admin_dashboard(request: Request, user=Depends(require_role("admin"))):
    return _render_dashboard(
        request,
        user,
        [
            "Review seeded accounts, unlock users, and manage blocked IPs.",
            "Review security alerts and view the tally after the poll closes.",
        ],
    )


@router.get("/auditor/dashboard")
def auditor_dashboard(request: Request, user=Depends(require_role("auditor"))):
    return _render_dashboard(
        request,
        user,
        [
            "Filter the audit timeline and verify ballot and audit integrity.",
            "View the closed election tally and generate a forensic report.",
        ],
    )