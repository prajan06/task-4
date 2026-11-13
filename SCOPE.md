# Scope, Authorization Statement and Rules of Engagement

**Engagement:** Defensive Security Assessment Capstone
**Target:** `secure-auth-lab` (this repository), a small Flask + SQLite authentication service written by the assessor
**Assessor / owner:** ______________________ (replace with your name)  **Date:** ______________

## 1. Authorization statement

I am the author and sole owner of the application under test and of the machine it runs on. I authorize myself to
test it as described below. No third-party system, account, network, or person is involved. This assessment is
defensive: the goal is to find weaknesses in my own code, fix them, and prove the fixes work.

Signed: ______________________

## 2. Scope

| In scope | Out of scope |
|---|---|
| All code in `auth_lab/` (routes `/register`, `/login`, `/logout`, `/me`) | Any system I do not own |
| Configuration: debug mode, cookie flags, headers, database file permissions | Network scanning, port scanning, DNS/OSINT |
| Authentication: hashing, lockout, generic errors, timing | Denial-of-service against shared infrastructure or the hosting machine |
| Session handling: rotation, logout, expiry | Social engineering, physical access |
| Input validation and error handling | Testing against real user data or real credentials |
| Dependencies (`requirements.txt`) | The Flask/Werkzeug libraries' own source code (only their versions are reviewed) |
| Logging and detection capability | |

## 3. Rules of engagement

1. **White-box and local only.** Tests run in-process through Flask's test client (no listening socket, no network traffic).
2. **Synthetic data only.** Usernames such as `alice` and the placeholder passphrase in `probes.py` are fictional.
   No real credential, personal data, or secret appears in this repository. IPs use RFC 5737 documentation ranges.
3. **Bounded load.** Each probe sends at most a few hundred requests to a throwaway database in a temp directory.
   There is no sustained or distributed load.
4. **Non-destructive.** Probes never touch files outside their temp directory; the temp directory is deleted afterwards.
5. **Stop conditions.** Stop and reassess if a probe affects anything outside the temp directory, or if any real
   credential or personal data is discovered in the repo.
6. **Evidence handling.** Evidence is raw probe output committed under `evidence/`. Before publishing, it is
   reviewed to confirm it contains no real data.
7. **Fix, then retest.** Every fixed finding gets its own commit, a regression test, and a re-run of the same probe.
8. **Disclosure.** The report is written to be shareable: findings describe the weakness and fix, never a live exploit
   against anyone else's system.

## 4. Method

White-box review of the source plus black-box style probes (`assessment/probes.py`) covering **configuration,
authentication, validation, dependencies, and logging**. Severity = likelihood x impact in the stated threat model
(local, single-user lab service that could later be exposed behind HTTPS).
