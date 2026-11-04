#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt

# Generate secrets locally so no signing or encryption keys are committed.
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
printf '\nSetup complete. See README.md for the run command.\n'