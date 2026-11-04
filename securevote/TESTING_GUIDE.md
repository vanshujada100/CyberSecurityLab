# SecureVote: Teacher Test Guide

This guide uses the seeded demo accounts. The default password is `Vote@2025!`. Generate each account's current OTP using the no-phone command in [README.md](../README.md); codes expire every 30 seconds.

## Before Testing

1. Run setup and start SecureVote using the README instructions.
2. Open `http://localhost:8000`. In Codespaces, forward port 8000.
3. Keep the server running. Use a second terminal to generate OTPs.
4. Use `officer01` to add any extra candidates before opening the poll.

## Walkthrough

1. **Login and 2FA:** Sign in as `voter01` with the correct password and OTP. Confirm the voter dashboard opens. Sign in again and submit a wrong OTP first; it should be rejected and logged.
2. **Brute-force lock:** Submit five wrong passwords for `voter05`. As admin, view `/admin/users` and `/admin/alerts`; confirm the account is locked. Use `/admin/blocked` to unlock it.
3. **Open the poll:** Sign in as `officer01`, open `/officer/panel`, add a candidate if needed, then select Open Election. The officer panel shows turnout, not results.
4. **Cast one vote:** Sign in as `voter01`, open Vote, choose a candidate, and save the receipt. Verify the receipt. Submit the vote again; it should be rejected and produce a HIGH alert.
5. **Check role restrictions:** As a voter, visit `/admin/results`; expect 403 and an IDS/audit record. As admin, request `/admin/results` while the election is OPEN; results should be denied.
6. **Close and tally:** As officer, close the poll. As admin, open `/admin/results`. As auditor, open `/auditor/results`. Both tallies should match; the auditor page is read-only.
7. **Injection detection:** At `/login`, submit `' OR 1=1 --` as the student ID. Expect a blocked response and an injection alert, not a database error.
8. **Forensics:** As auditor, view `/auditor/logs`, `/auditor/verify`, and `/auditor/report`. The report shows alerts, source IPs, locked accounts, blocked IPs, and the high/critical timeline.
9. **Tamper demonstration:** Use a disposable database. Stop the app, run `python tamper.py ballot`, restart the app, and open `/auditor/verify`. It should report a broken ballot, raise a CRITICAL alert, and show the compromised banner. Other modes are `ballot-hash`, `log`, `delete-log`, and `delete-ballot`.
10. **Credential stuffing (optional):** From a separate test IP, submit wrong passwords for three different known accounts within five minutes. Check for a HIGH alert and IP block. This blocks the test IP for five minutes.
11. **Rate limit (last):** Send 100 quick requests to `/health` from one IP. Expect HTTP 429 and then a temporary 403 block. The same IP cannot continue testing until the block expires or an admin unblocks it.

## Safe Reset

Tamper tests change the database, and a failed integrity check does not reset itself. For a clean repeat, stop the app and reseed the demo database with `python seed.py --reset` from the `securevote` directory. This deletes the configured database and recreates demo data; do not use it if you need to keep existing election data.