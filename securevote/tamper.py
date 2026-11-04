# FOR DEMONSTRATION ONLY: simulates an attacker with direct database access.
import argparse
import secrets
import sqlite3

from config import DB_PATH


def _show_change(table, row_id, before, after):
    print(f"Table: {table}")
    print(f"Row ID: {row_id}")
    print(f"Before: {before!r}")
    print(f"After: {after!r}")


def tamper(mode):
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        if mode in {"ballot", "ballot-hash"}:
            row = connection.execute(
                "SELECT id, ciphertext, hash FROM ballots ORDER BY rowid LIMIT 1"
            ).fetchone()
            if row is None:
                raise SystemExit("No ballot rows to change.")
            if mode == "ballot":
                before = row["ciphertext"]
                replacement = "A" if before[0] != "A" else "B"
                after = replacement + before[1:]
                connection.execute(
                    "UPDATE ballots SET ciphertext = ? WHERE id = ?",
                    (after, row["id"]),
                )
            else:
                before = row["hash"]
                after = secrets.token_hex(32)
                connection.execute(
                    "UPDATE ballots SET hash = ? WHERE id = ?",
                    (after, row["id"]),
                )
            table, row_id = "ballots", row["id"]
        elif mode in {"log", "delete-log"}:
            rows = connection.execute(
                "SELECT id, details FROM audit_log ORDER BY id"
            ).fetchall()
            if not rows:
                raise SystemExit("No audit_log rows to change.")
            row = rows[(len(rows) - 1) // 2]
            before = row["details"]
            if mode == "log":
                after = f"{before or ''} [tampered]"
                connection.execute(
                    "UPDATE audit_log SET details = ? WHERE id = ?",
                    (after, row["id"]),
                )
            else:
                after = "<deleted>"
                connection.execute("DELETE FROM audit_log WHERE id = ?", (row["id"],))
            table, row_id = "audit_log", row["id"]
        else:
            row = connection.execute(
                "SELECT id, ciphertext FROM ballots ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            if row is None:
                raise SystemExit("No ballot rows to delete.")
            before, after = row["ciphertext"], "<deleted>"
            connection.execute("DELETE FROM ballots WHERE id = ?", (row["id"],))
            table, row_id = "ballots", row["id"]

        connection.commit()
        _show_change(table, row_id, before, after)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description="Demonstrate direct database tampering.")
    parser.add_argument(
        "mode",
        choices=("ballot", "ballot-hash", "log", "delete-log", "delete-ballot"),
    )
    args = parser.parse_args()
    tamper(args.mode)


if __name__ == "__main__":
    main()