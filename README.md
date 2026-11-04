# CyberSecurityLab

## SecureVote setup

Run the setup script once from the `securevote` directory. It creates a virtual environment, installs requirements, creates local secrets in `.env`, and seeds demo users. It does not start the server.

Linux:

```bash
cd securevote
./setup.sh
```

Windows Command Prompt or PowerShell:

```powershell
cd securevote
.\setup.bat
```

## Run SecureVote

Linux:

```bash
cd securevote
venv/bin/uvicorn main:app --reload
```

Windows:

```powershell
cd securevote
.\venv\Scripts\python.exe -m uvicorn main:app --reload
```

Open `http://localhost:8000`.

## Test two-factor login without a phone

For the lab only, generate the current six-digit code from the seeded, encrypted TOTP secret in a second terminal. Replace `voter01` with the account you are signing in as. The code changes every 30 seconds; rerun the command if it expires. This does not bypass 2FA: it generates the same time-based code an authenticator app would generate.

Linux:

```bash
cd securevote
venv/bin/python -c 'from database import get_db; from auth import decrypt_totp_secret; import pyotp; db=get_db(); row=db.execute("SELECT totp_secret_enc FROM users WHERE student_id = ?", ("voter01",)).fetchone(); print(pyotp.TOTP(decrypt_totp_secret(row["totp_secret_enc"])).now()); db.close()'
```

Windows PowerShell:

```powershell
cd securevote
.\venv\Scripts\python.exe -c "from database import get_db; from auth import decrypt_totp_secret; import pyotp; db=get_db(); row=db.execute('SELECT totp_secret_enc FROM users WHERE student_id = ?', ('voter01',)).fetchone(); print(pyotp.TOTP(decrypt_totp_secret(row['totp_secret_enc'])).now()); db.close()"
```

## Windows cryptography setup issue

`setup.bat` upgrades pip and installs fresh wheels to avoid an old cached Windows `cryptography` wheel. If `_rust` still fails to load, use 64-bit Python 3.10+ and install the Microsoft Visual C++ 2015-2022 Redistributable (x64). Close the app, remove only the `securevote/venv` folder, and rerun `setup.bat`; keep `.env` and `securevote.db`.