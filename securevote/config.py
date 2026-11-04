import os

from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "securevote.db")
SECRET_KEY = os.getenv("SECRET_KEY")
FERNET_KEY = os.getenv("FERNET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        'SECRET_KEY is missing. Generate one with: '
        'python -c "import secrets; print(secrets.token_hex(32))"'
    )

if not FERNET_KEY:
    raise RuntimeError(
        'FERNET_KEY is missing. Generate one with: '
        'python -c "from cryptography.fernet import Fernet; '
        'print(Fernet.generate_key().decode())"'
    )