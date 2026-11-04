import sqlite3

from config import DB_PATH


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    # SQLite disables foreign-key enforcement unless each connection enables it.
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    connection = get_db()
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                student_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('voter', 'officer', 'admin', 'auditor')),
                totp_secret_enc TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT
            );

            CREATE TABLE IF NOT EXISTS voter_status (
                user_id INTEGER PRIMARY KEY REFERENCES users(id),
                has_voted INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                position TEXT NOT NULL,
                description TEXT
            );

            -- Ballots intentionally have no user identifier or precise timestamp to protect secrecy.
            CREATE TABLE IF NOT EXISTS ballots (
                id TEXT PRIMARY KEY,
                ciphertext TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS election (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                state TEXT NOT NULL CHECK(state IN ('NOT_STARTED', 'OPEN', 'CLOSED')),
                opened_at TEXT,
                closed_at TEXT,
                integrity_status TEXT DEFAULT 'OK'
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                actor_id TEXT,
                role TEXT,
                ip TEXT,
                user_agent TEXT,
                details TEXT,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ids_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip TEXT,
                user_id TEXT,
                details TEXT,
                status TEXT DEFAULT 'OPEN'
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                blocked_until TEXT NOT NULL
            );
            """
        )
        connection.commit()
    finally:
        connection.close()