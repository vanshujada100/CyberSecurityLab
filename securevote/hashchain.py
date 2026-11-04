import hashlib

GENESIS = "0" * 64


def compute_hash(prev_hash, *fields):
    values = (prev_hash, *fields)
    joined = "|".join("" if value is None else str(value) for value in values)
    return hashlib.sha256(joined.encode()).hexdigest()


def get_last_ballot_hash(db):
    row = db.execute("SELECT hash FROM ballots ORDER BY rowid DESC LIMIT 1").fetchone()
    return row["hash"] if row else GENESIS


def verify_ballot_chain(db):
    expected_prev = GENESIS
    checked = 0
    rows = db.execute("SELECT id, ciphertext, prev_hash, hash FROM ballots ORDER BY rowid")
    for row in rows:
        checked += 1
        if row["prev_hash"] != expected_prev:
            return {
                "ok": False,
                "checked": checked,
                "broken_at": row["id"],
                "reason": "prev_hash mismatch",
            }
        expected_hash = compute_hash(row["prev_hash"], row["ciphertext"], row["id"])
        if row["hash"] != expected_hash:
            return {
                "ok": False,
                "checked": checked,
                "broken_at": row["id"],
                "reason": "hash mismatch",
            }
        expected_prev = row["hash"]
    return {"ok": True, "checked": checked, "broken_at": None, "reason": "all records verified"}


def verify_audit_chain(db):
    expected_prev = GENESIS
    checked = 0
    rows = db.execute(
        """SELECT id, ts, event_type, severity, actor_id, role, ip, details,
                  prev_hash, hash
           FROM audit_log ORDER BY id"""
    )
    for row in rows:
        checked += 1
        if row["prev_hash"] != expected_prev:
            return {
                "ok": False,
                "checked": checked,
                "broken_at": row["id"],
                "reason": "prev_hash mismatch",
            }
        expected_hash = compute_hash(
            row["prev_hash"],
            row["ts"],
            row["event_type"],
            row["severity"],
            row["actor_id"],
            row["role"],
            row["ip"],
            row["details"],
        )
        if row["hash"] != expected_hash:
            return {
                "ok": False,
                "checked": checked,
                "broken_at": row["id"],
                "reason": "hash mismatch",
            }
        expected_prev = row["hash"]
    return {"ok": True, "checked": checked, "broken_at": None, "reason": "all records verified"}


def verify_ballot_count(db):
    ballots = db.execute("SELECT COUNT(*) FROM ballots").fetchone()[0]
    voted = db.execute(
        "SELECT COUNT(*) FROM voter_status WHERE has_voted = ?", (1,)
    ).fetchone()[0]
    return {"ok": ballots == voted, "ballots": ballots, "voted": voted}