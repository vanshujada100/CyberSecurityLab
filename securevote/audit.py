from datetime import datetime, timezone
import threading

from database import get_db
from hashchain import GENESIS, compute_hash

_audit_lock = threading.Lock()


def log_event(event_type, severity, actor_id, role, ip, user_agent, details):
    timestamp = datetime.now(timezone.utc).isoformat()
    # Serializing each append prevents concurrent writers from forking the audit chain.
    with _audit_lock:
        connection = get_db()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = row["hash"] if row else GENESIS
            event_hash = compute_hash(
                previous_hash,
                timestamp,
                event_type,
                severity,
                actor_id,
                role,
                ip,
                details,
            )
            connection.execute(
                """INSERT INTO audit_log
                   (ts, event_type, severity, actor_id, role, ip, user_agent,
                    details, prev_hash, hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    timestamp,
                    event_type,
                    severity,
                    actor_id,
                    role,
                    ip,
                    user_agent,
                    details,
                    previous_hash,
                    event_hash,
                ),
            )
            connection.commit()
            return event_hash
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def get_client(request):
    client_ip = request.client.host if request.client else "unknown"
    return client_ip, request.headers.get("user-agent", "")