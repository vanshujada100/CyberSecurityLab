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
            ("Results", "/admin/results"),
            ("Alerts", "/admin/alerts"),
            ("Blocked IPs and locked users", "/admin/blocked"),
        ],
        "auditor": [],
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
        ["Review election information (available in a later phase)."],
    )


@router.get("/officer/dashboard")
def officer_dashboard(request: Request, user=Depends(require_role("officer"))):
    return _render_dashboard(
        request,
        user,
        ["Manage election operations (available in a later phase)."],
    )


@router.get("/admin/dashboard")
def admin_dashboard(request: Request, user=Depends(require_role("admin"))):
    return _render_dashboard(
        request,
        user,
        ["Manage SecureVote configuration (available in a later phase)."],
    )


@router.get("/auditor/dashboard")
def auditor_dashboard(request: Request, user=Depends(require_role("auditor"))):
    return _render_dashboard(
        request,
        user,
        ["Review election integrity information (available in a later phase)."],
    )