# SecureVote Lab Documentation

## Purpose

SecureVote is a local college election demonstration built with FastAPI, SQLite, and Jinja2. It shows authentication, role-based access control, ballot secrecy, cryptographic integrity, intrusion detection/prevention, and forensic review. It is a teaching application, not a production election service.

Use the platform-specific setup and run instructions in the repository [README](../README.md). Demo accounts are created by `seed.py`; the seed output displays their shared demo password and each TOTP secret. To test without a phone, use the terminal TOTP command in the README.

## Application Flow

1. A user submits their student ID and password. Passwords are checked with bcrypt, and unknown IDs follow the same bcrypt path.
2. A correct password receives a short-lived pre-2FA token. A valid TOTP code replaces it with a short-lived full-access token.
3. RBAC checks the token stage and role, then rechecks the current role in SQLite so database role changes take effect immediately.
4. An officer adds candidates before the poll opens, opens and closes the election, and monitors turnout. The officer cannot view results.
5. A voter can cast one vote while the election is open. The encrypted ballot is stored separately from voter status; the voter receives a random receipt whose hash is stored.
6. An admin can review seeded accounts, unlock accounts, manage blocked IPs, and inspect alerts. After close, the admin can view the decrypted tally and an auditor can view it read-only; auditors can also inspect logs, verify integrity, and generate a forensic report.

## Security Mechanisms

| Mechanism | What and why | Implementation | Demonstration |
|---|---|---|---|
| Authentication | bcrypt password hashes, generic credential errors, TOTP second factor, and short-lived JWT cookies reduce password disclosure, account enumeration, and session exposure. | `auth.py`, `routes/auth_routes.py` | Log in with a seeded account, generate a current OTP from the README command, then try a wrong OTP. |
| Account protection | Five failed password or TOTP attempts within ten minutes lock a known account for 15 minutes. Three distinct known account IDs failing from one IP within five minutes raise a credential-stuffing alert and block that IP. | `ids.py`, `routes/auth_routes.py` | Submit failed attempts for one account, then for three accounts from the same IP; review `/admin/alerts` and `/admin/blocked`. |
| Authorization and access control | `require_role()` denies by default; each protected page declares its role. The current database role is rechecked rather than trusting a possibly stale JWT claim. | `rbac.py`, `routes/` | Sign in as a voter and request an admin page; expect 403, an audit event, and an IDS alert. |
| Election state controls | Voting is accepted only while OPEN. Candidate changes are limited to NOT_STARTED, and opening/closing follows the election state machine. | `routes/officer.py`, `routes/voter.py` | Try voting before open and after close; try adding a candidate after opening. |
| Ballot secrecy | Fernet encrypts the candidate ID with a random nonce. `voter_status` records who voted; `ballots` has no voter ID or timestamp. A SHA-256 receipt hash allows inclusion checks without revealing the selection. | `crypto_utils.py`, `routes/voter.py`, `database.py` | Cast a vote, inspect the ballot row, and verify the receipt. The ballot view should not identify the candidate. |
| Atomic voting | `BEGIN IMMEDIATE` and the conditional `has_voted = 0` update serialize competing vote attempts, preventing a second ballot. | `routes/voter.py` | Submit the ballot twice; the second attempt is rejected and creates a HIGH alert. |
| Hash integrity | Ballot and audit rows include the previous hash. Verification recomputes each row and reports the first break. A ballot-count comparison also catches deletion of the last ballot. | `hashchain.py`, `audit.py`, `routes/auditor.py` | Run a `tamper.py` mode, then open `/auditor/verify`. |
| Audit logging | Security events are appended with UTC time, actor, role, source, details, and a chained hash. `BEGIN IMMEDIATE` serializes writes; there are no audit update/delete routes. | `audit.py`, route modules | Review `/auditor/logs` and filter by actor, IP, event type, severity, or date. |
| IDS and IPS | Detects brute force, credential stuffing, duplicate and out-of-window votes, privilege probing, injection signatures, and excessive request rates. Blocks are stored with an expiry and can be manually cleared by an admin. | `ids.py`, `main.py`, `routes/admin.py` | Review alerts, trigger a signature or rate threshold, and inspect `/admin/blocked`. Run rate testing last because the source IP is temporarily blocked. |
| Browser protections | Same-origin CSS works with the restrictive CSP. Responses include frame, content-type, and cache-control protections; Jinja2 autoescaping reduces reflected/stored XSS risk. | `main.py`, `templates/base.html`, `static/style.css` | Inspect response headers and try a harmless script-signature string in a query parameter; the request should be rejected. |

## Storage and Data Separation

- `users` holds account identity, bcrypt hash, encrypted TOTP secret, role, and lockout fields.
- `voter_status` stores whether each eligible user has voted; it does not store a candidate.
- `ballots` stores only a random ID, encrypted ciphertext, receipt hash, and hash-chain fields. It has no user ID or timestamp.
- `candidates` stores choices and positions. The tally decrypts ballots only after the election is CLOSED.
- `audit_log` and `ids_alerts` hold security and investigation events; `blocked_ips` stores temporary block expiry.

The schema is intentionally small for the lab. Demo election records and users persist in `securevote.db` unless that database is removed or reseeded with the seed script's reset option.

## Manual Demonstration Sequence

1. Run setup using the README, start the app, and sign in as `voter01` with its seeded password and current TOTP code.
2. Try a wrong TOTP once and confirm it is rejected and logged.
3. Submit five wrong passwords for one account. Review it at `/admin/users`, verify its lock and the brute-force alert, then unlock it from `/admin/blocked` as admin.
4. Sign in as `officer01`, add a candidate, and open the election.
5. Sign in as a voter, cast a vote, save the receipt, and verify that it is found. Confirm the voter status is set and the ballot ciphertext is not plaintext.
6. Resubmit the vote. Confirm rejection and a HIGH double-vote alert.
7. As a voter, request `/admin/results`; confirm 403, audit logging, and IDS alerting.
8. While the poll is OPEN, try `/admin/results` as admin; it must be denied.
9. Close the election as officer. View results as admin and as auditor; confirm the auditor has read-only access and both tallies match the demo votes.
10. Submit `' OR 1=1 --` in the student ID field. Confirm a blocked request and injection alert without a database error.
11. As auditor, inspect logs, run integrity verification, and generate `/auditor/report`.
12. For tamper demonstrations, use a disposable copy of the database. Run `python tamper.py ballot`, then verify integrity; repeat with `ballot-hash`, `log`, `delete-log`, or `delete-ballot` as desired. A failed verification marks the election COMPROMISED and raises a CRITICAL alert; this status is not automatically reset.
13. Run the 100-request rate-limit demonstration last. The source IP receives HTTP 429 and is blocked temporarily; subsequent requests from that IP receive 403 until expiry or admin unblock.

## Lab Limitations

- JWT revocation and request counters are in memory; they reset when the process restarts and are not shared across multiple workers.
- SQLite and local `.env` keys are demonstration storage, not managed production key infrastructure.
- The TOTP terminal helper exposes a current code to the local operator; it is only a substitute for an authenticator during this lab.
- Rate limits are source-IP based, so testing through a proxy or shared address affects other requests from that address.
- The hash checks detect changes relative to the stored chain; an attacker with full database and key control could rewrite all related data. This is tamper evidence for a lab, not a public verifiable voting protocol.