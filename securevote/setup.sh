#!/usr/bin/env bash
set -eu

cd "$(dirname "$0")"

python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt

# Generate local secrets only when absent or still using example placeholders.
venv/bin/python - <<'PY'
from pathlib import Path
import secrets

from cryptography.fernet import Fernet

env_path = Path(".env")
if not env_path.exists():
    env_path.write_text(Path(".env.example").read_text())

lines = env_path.read_text().splitlines()
generators = {
    "SECRET_KEY": lambda: secrets.token_hex(32),
    "FERNET_KEY": lambda: Fernet.generate_key().decode(),
}

for key, generate in generators.items():
    matches = [index for index, line in enumerate(lines) if line.startswith(f"{key}=")]
    current = lines[matches[-1]].split("=", 1)[1].strip().strip("\"'") if matches else ""
    if not current or current.startswith("replace_with_"):
        value = generate()
        if matches:
            lines[matches[-1]] = f"{key}={value}"
        else:
            lines.append(f"{key}={value}")

env_path.write_text("\n".join(lines) + "\n")
PY

venv/bin/python seed.py

if venv/bin/python - <<'PY'
import json
from urllib.request import urlopen

try:
    with urlopen("http://127.0.0.1:8000/health", timeout=2) as response:
        health = json.load(response)
    already_running = health.get("status") == "ok" and "election_state" in health
except Exception:
    already_running = False

raise SystemExit(0 if already_running else 1)
PY
then
    printf '\nSecureVote is already running at http://localhost:8000.\n'
    exit 0
fi

printf '\nSecureVote is starting at http://localhost:8000 (open /health to check it).\n'
exec venv/bin/uvicorn main:app --reload --host 0.0.0.0 --port 8000