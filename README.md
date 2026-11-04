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