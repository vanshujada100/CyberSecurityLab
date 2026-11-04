@echo off
setlocal
cd /d "%~dp0"

py -3 -m venv venv
if errorlevel 1 goto failed

venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto failed

:: Fix DLL import issues on Windows Python 3.9
venv\Scripts\python.exe -m pip install "bcrypt<4.0.0" "cryptography<41.0.0"
if errorlevel 1 goto failed

if not exist .env copy .env.example .env
if errorlevel 1 goto failed

venv\Scripts\python.exe -c "from pathlib import Path; import secrets; from cryptography.fernet import Fernet; p=Path('.env'); t=p.read_text(); t=t.replace('SECRET_KEY=replace_with_generated_secret_key','SECRET_KEY='+secrets.token_hex(32)).replace('FERNET_KEY=replace_with_generated_fernet_key','FERNET_KEY='+Fernet.generate_key().decode()); p.write_text(t)"
if errorlevel 1 goto failed

venv\Scripts\python.exe seed.py
if errorlevel 1 goto failed

echo.
echo Setup complete. Starting SecureVote at http://localhost:8000...
venv\Scripts\uvicorn.exe main:app --reload --host 0.0.0.0 --port 8000
exit /b 0

:failed
echo Setup failed. Check that Python 3 and the py launcher are installed.
exit /b 1