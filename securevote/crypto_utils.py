import json
import secrets

from cryptography.fernet import Fernet

from config import FERNET_KEY


def encrypt_ballot(candidate_id):
    # A random nonce prevents identical selections from producing identical ballot payloads.
    payload = json.dumps(
        {"c": candidate_id, "n": secrets.token_hex(16)},
        separators=(",", ":"),
    ).encode()
    return Fernet(FERNET_KEY.encode()).encrypt(payload).decode()


def decrypt_ballot(ciphertext):
    payload = Fernet(FERNET_KEY.encode()).decrypt(ciphertext.encode())
    return json.loads(payload)["c"]


def tally_ballots(db):
    candidates = db.execute(
        "SELECT id, name, position FROM candidates ORDER BY position, name"
    ).fetchall()
    counts = {candidate["id"]: 0 for candidate in candidates}
    for row in db.execute("SELECT ciphertext FROM ballots").fetchall():
        candidate_id = decrypt_ballot(row["ciphertext"])
        if candidate_id in counts:
            counts[candidate_id] += 1
    return [
        {
            "name": candidate["name"],
            "position": candidate["position"],
            "votes": counts[candidate["id"]],
        }
        for candidate in candidates
    ]