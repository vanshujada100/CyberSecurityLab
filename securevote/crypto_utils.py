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