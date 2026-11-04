# HACKII PREDICT — Render deployment

## Files
- `index.html`: existing user panel UI, changed only to use server-issued login keys and the server-side WinGo API proxy.
- `admin.html`: admin key generator, expiry/device limits, online sessions, revoke controls.
- `app.py`: Flask API and SQLite persistence.
- `render.yaml`: Render web service plus persistent disk.

## Deploy
1. Upload this folder to a GitHub repository.
2. Create a Render Blueprint from the repository (or create a Python web service).
3. Ensure the persistent disk is mounted at `/var/data`; SQLite DB is `/var/data/hackii.sqlite3`. Without persistent disk, keys and sessions may be lost on redeploy/restart.
4. In Render Environment set only `ADMIN_MASTER_KEY` to a long, unique secret (at least 32 random characters). The database path is fixed at `/var/data/hackii.sqlite3`; no extra environment variable is needed.
5. Deploy. Open `/admin`, enter the same `ADMIN_MASTER_KEY`, generate user login keys, and share each generated key.
6. Users open the service URL and sign in using the generated key.

## Notes
- Generated user keys are stored as SHA-256 hashes; the plaintext is shown once at creation.
- Active status is based on heartbeat in the last 90 seconds. User panel sends a heartbeat every 30 seconds.
- Member name / Telegram ID is optional and supplied by the user at login; device detail is based on browser user-agent. No IP address is stored.
- Each key has a configurable concurrent device/session limit and expiry. Revoking a key ends all sessions.
- The API proxy requires a valid user session and avoids browser CORS issues. Upstream API availability remains outside this app's control.
- Use HTTPS (Render default) and keep `ADMIN_MASTER_KEY` private. Do not commit it to GitHub.


PRIVACY / BROWSER ID
The user panel creates a random anonymous Browser ID in that browser profile storage (example: BR-0123456789ABCDEF). Admin sees only this ID, associated login key hint, login time, last seen, and online/offline status. No personal name, phone, email, Telegram ID, or browser user-agent is requested or stored. Clearing site data, using private/incognito mode, or switching browser profiles may create a new Browser ID. This is not a hardware ID or Google/Chrome account ID.
