import argparse
import os
from pathlib import Path

import bcrypt
import pyotp
from cryptography.fernet import Fernet

from config import DB_PATH, FERNET_KEY
from database import get_db, init_db


def seed_database():
    init_db()
    connection = get_db()
    try:
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
            print("Users already exist; seed skipped.")
            return

        connection.execute(
            "INSERT INTO election (id, state) VALUES (?, ?)",
            (1, "NOT_STARTED"),
        )

        candidates = [
            ("Alex Morgan", "Student Council President", "Focus on student services."),
            ("Jordan Lee", "Student Council President", "Focus on campus accessibility."),
            ("Taylor Kim", "Student Council President", "Focus on transparent budgeting."),
        ]
        connection.executemany(
            "INSERT INTO candidates (name, position, description) VALUES (?, ?, ?)",
            candidates,
        )

        demo_users = [
            ("admin01", "Demo Admin", "admin"),
            ("officer01", "Demo Officer", "officer"),
            ("auditor01", "Demo Auditor", "auditor"),
            ("voter01", "Demo Voter 1", "voter"),
            ("voter02", "Demo Voter 2", "voter"),
            ("voter03", "Demo Voter 3", "voter"),
            ("voter04", "Demo Voter 4", "voter"),
            ("voter05", "Demo Voter 5", "voter"),
        ]
        password = "Vote@2025!"
        cipher = Fernet(FERNET_KEY.encode())
        credentials = []

        for student_id, name, role in demo_users:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            totp_secret = pyotp.random_base32()
            totp_secret_enc = cipher.encrypt(totp_secret.encode()).decode()
            connection.execute(
                """INSERT INTO users
                   (student_id, name, password_hash, role, totp_secret_enc)
                   VALUES (?, ?, ?, ?, ?)""",
                (student_id, name, password_hash, role, totp_secret_enc),
            )
            if role == "voter":
                user_id = connection.execute(
                    "SELECT id FROM users WHERE student_id = ?", (student_id,)
                ).fetchone()[0]
                connection.execute(
                    "INSERT INTO voter_status (user_id, has_voted) VALUES (?, ?)",
                    (user_id, 0),
                )
            provisioning_uri = pyotp.TOTP(totp_secret).provisioning_uri(
                name=student_id,
                issuer_name="SecureVote",
            )
            credentials.append((student_id, role, password, totp_secret, provisioning_uri))

        connection.commit()
    finally:
        connection.close()

    print("Demo credentials (plaintext secrets are printed for this demo only):")
    print("student_id | role | password | TOTP secret | provisioning URI")
    for credential in credentials:
        print(" | ".join(credential))


def main():
    parser = argparse.ArgumentParser(description="Seed SecureVote demo data.")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete the configured SQLite database before seeding.",
    )
    args = parser.parse_args()

    if args.reset:
        database_path = Path(DB_PATH)
        if database_path.exists():
            os.remove(database_path)

    seed_database()


if __name__ == "__main__":
    main()