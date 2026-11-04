# SecureVote: Permission Matrix

Use this table to check which role may open each page or perform each action. A user must complete both password and OTP login before using protected pages.

| Page or action | Public | Voter | Officer | Admin | Auditor | Notes |
|---|---:|---:|---:|---:|---:|---|
| `/`, `/login`, `/health`, `/static/*` | Yes | Yes | Yes | Yes | Yes | Public entry and status resources. |
| Submit password at `/login` | Yes | Yes | Yes | Yes | Yes | Success grants only the pre-2FA step. |
| `/verify-2fa` | Pre-2FA | Pre-2FA | Pre-2FA | Pre-2FA | Pre-2FA | A valid OTP grants full access. |
| `/dashboard` | No | Yes | Yes | Yes | Yes | Redirects to the user's role dashboard. |
| `/voter/dashboard`, `/vote` | No | Yes | No | No | No | Vote only while the election is OPEN; one ballot per voter. |
| `/verify-receipt` | No | Yes | No | No | No | Voter can check a receipt without seeing the choice. |
| `/officer/dashboard`, `/officer/panel` | No | No | Yes | No | No | Panel shows turnout and candidates, never results. |
| Add candidate, open/close election | No | No | Yes | No | No | Candidate changes only before opening. |
| `/admin/dashboard`, `/admin/users` | No | No | No | Yes | No | View seeded users and unlock locked accounts. |
| `/admin/alerts`, `/admin/blocked` | No | No | No | Yes | No | View alerts, blocked IPs, and locked accounts. |
| Unblock IP or unlock user | No | No | No | Yes | No | Admin action; it is logged. |
| `/admin/results` | No | No | No | Yes | No | Available only after election close. |
| `/auditor/dashboard`, `/auditor/logs` | No | No | No | No | Yes | Read-only audit history and filters. |
| `/auditor/verify`, `/auditor/report` | No | No | No | No | Yes | Verification may mark integrity compromised and raise an alert. |
| `/auditor/results` | No | No | No | No | Yes | Read-only tally; available only after election close. |
| `POST /logout` | Yes | Yes | Yes | Yes | Yes | Revokes the current token when present and clears the cookie. |

Unauthorized protected-page access returns 401 or 403, is recorded, and is sent to the IDS. Three role violations by one signed-in user within five minutes raise a privilege-probing alert and revoke that token.