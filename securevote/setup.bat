@echo off
setlocal
cd /d "%~dp0"

py -3 -m venv venv
if errorlevel 1 goto failed

venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto failed

if not exist .env copy .env.example .env
if errorlevel 1 goto failed

venv\Scripts\python.exe -c "from pathlib import Path; import secrets; from cryptography.fernet import Fernet; p=Path('.env'); t=p.read_text(); t=t.replace('SECRET_KEY=replace_with_generated_secret_key','SECRET_KEY='+secrets.token_hex(32)).replace('FERNET_KEY=replace_with_generated_fernet_key','FERNET_KEY='+Fernet.generate_key().decode()); p.write_text(t)"
if errorlevel 1 goto failed

venv\Scripts\python.exe seed.py
if errorlevel 1 goto failed

echo.
echo Setup complete. See README.md for the run command.
exit /b 0

:failed
echo Setup failed. Check that Python 3 and the py launcher are installed.
exit /b 1