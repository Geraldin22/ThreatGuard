# ThreatGuard — Phishing Guard (Flask + SQLite)

A phone-installable web app (PWA) that scans SMS / chat / email text for phishing
phrases and risky links, scores it 0–100, and stores every result in SQLite.

## Run it

```bash
cd phishguard
pip install -r requirements.txt
export PHISHGUARD_TOKEN="pick-a-long-random-key"   # protects the API
python app.py                                      # http://localhost:5000
```

Production: `gunicorn -w 2 -b 0.0.0.0:8000 app:app`

| Env var | Purpose | Default |
|---|---|---|
| `PHISHGUARD_TOKEN` | API key (sent as `X-API-Key`). The app asks for it once and remembers it. | none (open) |
| `PHISHGUARD_DB` | SQLite file path | `phishguard.db` |
| `PORT` / `HOST` | Server bind | `5000` / `0.0.0.0` |

## Put it on your phone

Phones only install PWAs and use Share targets over **HTTPS**, so host it somewhere with a
certificate (a small VPS, Render/Fly/Railway, or a tunnel such as Cloudflare Tunnel / ngrok for testing).
Always set `PHISHGUARD_TOKEN` when it is reachable from the internet.

1. Open the HTTPS URL in **Chrome on Android** → menu → **Install app** / **Add to Home screen**.
2. In the app: **Inbox → Allow access**.

### Ways to get messages into it

1. **Share (works today, Android):** long-press a message in your messaging app → **Share** →
   **ThreatGuard**. It opens, scans, shows the highlighted result and saves it.
2. **Copy/paste:** Scan page → paste → *Scan now*.
3. **Automatic forwarding (Android):** use an automation app (Tasker, MacroDroid, Automate) with an
   "SMS received" trigger and an HTTP POST action:

   ```
   POST https://YOUR-HOST/api/messages
   X-API-Key: <your token>
   Content-Type: application/json

   {"sender": "%SMSRF", "channel": "SMS", "body": "%SMSRB"}
   ```
   (`%SMSRF` / `%SMSRB` are Tasker variables for sender and body; other apps use different names.)
   The response contains `level`, `score` and `status`, so the automation can notify you on `high`.

## What it can't do (important)

A web app cannot read your SMS inbox or other apps' notifications, and it cannot block or delete
messages in them. That needs a native Android app with SMS / notification-listener permissions
(iOS does not allow it at all for third-party apps). "Blocked" here means ThreatGuard marks the message
and disables the link inside *its own* view. The detector is a keyword/link rule engine, not machine
learning, so expect both misses and false alarms.

## API

| Method | Path | Notes |
|---|---|---|
| GET | `/api/state` | `{access, auth_required}` |
| POST | `/api/access` | `{"allowed": true/false}`; turning off archives the inbox |
| POST | `/api/messages` | ingest `{sender, channel, body}` (403 while access is off) |
| POST | `/api/scan` | manual scan, always allowed |
| GET | `/api/messages?limit=50` | newest first, includes highlight ranges |
| POST | `/api/inbox/clear` | hides inbox items; history and stats are kept |
| GET | `/api/stats` | `{total, high, clean}` |

## Files

- `app.py` Flask app and API · `detector.py` scoring rules · `schema.sql` SQLite tables (`messages`, `settings`)
- `static/` your UI (now calling the API), `manifest.webmanifest` (install + share target), `sw.js`, `icon.svg`
- `test_app.py` run with `pytest`
