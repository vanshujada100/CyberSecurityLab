# SecureVote: Security Mechanisms

SecureVote is a local college election lab app. This guide explains what each security feature does, where it is implemented, and how to demonstrate it. Setup and test steps are in [README.md](../README.md) and [TESTING_GUIDE.md](TESTING_GUIDE.md).

| Mechanism | What it does | Where | How to show it |
|---|---|---|---|
| Password and 2FA login | bcrypt stores password hashes. TOTP adds a second step. JWT cookies expire after login. Generic errors make it harder to discover valid student IDs. | `auth.py`, `routes/auth_routes.py` | Sign in with a correct password and OTP, then try a wrong OTP. |
| Account protection | Five failed logins or OTPs lock an account for 15 minutes. Failures against three known accounts from one IP raise a credential-stuffing alert and block that IP. | `ids.py`, `routes/auth_routes.py` | Use wrong credentials and inspect the Admin Users and Alerts pages. |
| Roles and permissions | Pages require the right role. The app checks the role in the database on each protected request, so role changes take effect immediately. | `rbac.py`, `routes/` | Sign in as a voter and try an admin or officer page. |
| Election controls | Only an officer can manage candidates and change the poll state. Voting and results are restricted by election state. | `routes/officer.py`, `routes/voter.py`, `routes/admin.py`, `routes/auditor.py` | Try voting before open and view results before close. |
| Ballot secrecy | Fernet encrypts each choice with a random nonce. Voter status is stored separately from ballots. A receipt hash confirms inclusion without identifying the choice. | `crypto_utils.py`, `routes/voter.py`, SQLite tables | Vote, verify the receipt, then inspect the ballot row; it contains no voter ID or timestamp. |
| Hash integrity | Ballots and audit entries include the previous record hash. Verification reports the first broken record. A separate count check catches a deleted final ballot. | `hashchain.py`, `audit.py`, `routes/auditor.py` | Run a `tamper.py` mode on a disposable database, then use Auditor Verify. |
| IDS and IPS | Detects brute force, credential stuffing, duplicate or out-of-window votes, privilege probing, injection patterns, and excessive requests. It raises alerts and temporarily blocks IPs. | `ids.py`, `main.py`, `routes/admin.py` | Trigger a rule, then inspect Admin Alerts and Blocked IPs. Run the rate test last. |
| Audit and forensics | Security events are appended to a hash-chained log. Auditors can filter logs, verify integrity, view the closed tally, and generate a report. | `audit.py`, `routes/auditor.py` | Review Auditor Logs, Verify, Results, and Report. |
| Browser protections | Same-origin CSS works with the Content Security Policy. Jinja2 autoescaping and response headers provide basic browser protections. | `main.py`, `templates/base.html`, `static/style.css` | Inspect response headers and submit a harmless injection signature. |

## Data Separation

- `voter_status` records whether a user voted; it does not identify a choice.
- `ballots` stores encrypted choices, receipt hashes, and chain hashes. It has no user ID or vote timestamp.
- The tally decrypts choices only after the election closes. Admin and Auditor results are read-only.
- `audit_log`, `ids_alerts`, and `blocked_ips` keep investigation and response information separate from ballots.

## Lab Limits

- JWT revocation and request counters are in memory and reset when the app restarts.
- SQLite and `.env` keys are for a local demonstration, not production key management.
- The terminal OTP helper is for this lab only; it generates a real TOTP code from the encrypted demo secret.
- These hash checks provide tamper evidence. They are not a public end-to-end-verifiable voting protocol.