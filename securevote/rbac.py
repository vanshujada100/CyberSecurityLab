from fastapi import HTTPException, Request

from auth import decode_token
from database import get_db
from ids import record_privilege_violation


def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    claims = decode_token(token) if token else None
    if not claims or claims.get("stage") != "full":
        raise HTTPException(status_code=401, detail="Authentication required.")

    user_id = claims.get("sub")
    if not isinstance(user_id, str) or not user_id.isascii() or not user_id.isdigit():
        raise HTTPException(status_code=401, detail="Authentication required.")

    connection = get_db()
    try:
        row = connection.execute(
            "SELECT id, student_id, name, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        connection.close()

    if row is None or row["role"] != claims.get("role"):
        # Rechecking the DB makes role changes effective; routes grant only least privilege.
        raise HTTPException(status_code=401, detail="Authentication required.")
    return dict(row)


def require_role(*allowed_roles):
    def role_dependency(request: Request):
        user = get_current_user(request)
        if user["role"] not in allowed_roles:
            record_privilege_violation(request, user)
            raise HTTPException(status_code=403, detail="Access denied.")
        return user

    return role_dependency