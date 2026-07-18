# Sentinel AI — Gmail Integration Setup

This guide covers the **external Google configuration** and the **local/Docker
configuration** needed to connect a real Gmail mailbox to Sentinel with Google
OAuth. None of these secrets are committed to the repo — you create them in
your own Google Cloud project and put them in your `.env` (or Render
dashboard).

> **Scope & honesty note.** Sentinel supports **one active Gmail connection per
> deployment**. Push (Pub/Sub) is **optional**; **polling is the default and
> works with zero extra infrastructure**. `gmail.modify` is a Google
> *restricted scope*: **Testing mode + test users** is enough for a demo, but a
> public production launch requires Google verification and a CASA security
> assessment (see §33–34).

---

## 1. Create a Google Cloud project
1. Go to <https://console.cloud.google.com/> → project picker → **New Project**.
2. Name it (e.g. `sentinel-ai`) and create it.

## 2. Enable the Gmail API
1. **APIs & Services → Library** → search **Gmail API** → **Enable**.

## 3. Configure the OAuth consent screen
1. **APIs & Services → OAuth consent screen**.
2. **User type**:
   - **Internal** — only if you have a Google Workspace org and will connect an
     org mailbox (no verification needed).
   - **External** — any Gmail account; stays in **Testing** mode (fine for a
     capstone/demo).
3. Fill app name, support email, developer email.
4. **Scopes**: you can leave the scope list empty here — Sentinel requests them
   at runtime. The scopes it uses are:
   - `openid`, `.../auth/userinfo.email` — identify the connected account
   - `.../auth/gmail.modify` — read messages + add/remove labels (this is what
     makes quarantine = add label + remove `INBOX`; it **cannot permanently
     delete** mail)

## 4. Internal vs External
- **Internal**: no test users, no verification — simplest if you have Workspace.
- **External + Testing**: add **test users** (§8); each connected account must
  be listed there. No verification needed while in Testing.

## 5–7. Create the OAuth **Web** client (Client ID + Secret + redirect URIs)
1. **APIs & Services → Credentials → Create Credentials → OAuth client ID**.
2. **Application type: Web application**.
3. **Authorised redirect URIs** — add **exactly** the callback URL:
   - Local: `http://localhost:5000/api/admin/gmail/callback`
   - Docker: `http://localhost:5000/api/admin/gmail/callback`
   - Render/prod: `https://<your-app>.onrender.com/api/admin/gmail/callback`
   The value must match `GOOGLE_OAUTH_REDIRECT_URI` byte-for-byte.
4. Create → copy the **Client ID** and **Client secret**.

## 8. Add test users (External/Testing only)
- **OAuth consent screen → Test users → Add users** → add the Gmail address(es)
  you'll connect. Without this you'll get `access_blocked` on consent.

## 9. Generate the token-encryption key
```bash
cd backend
python crypto.py generate-key      # prints a Fernet key
```
Put it in `TOKEN_ENCRYPTION_KEY`. It encrypts refresh tokens at rest and is
**separate** from `SENTINEL_SECRET_KEY`. In a multi-service deploy
(web+worker+beat) all three must share the **same** value.

## 10. Configure `.env`
Copy `backend/.env.example` → `backend/.env` and set:
```
GOOGLE_CLIENT_ID=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=...
GOOGLE_OAUTH_REDIRECT_URI=http://localhost:5000/api/admin/gmail/callback
TOKEN_ENCRYPTION_KEY=<from step 9>
GMAIL_MONITORING_MODE=polling
GMAIL_POLL_SECONDS=60
GMAIL_MAX_MESSAGES_PER_SYNC=100
```

## 11–14. Start the app + background jobs
Local (four terminals, from `backend/`):
```bash
python -m alembic upgrade head      # migrate DB
python app.py                       # web (http://localhost:5000)
celery -A celery_app worker --loglevel=info    # runs the sync
celery -A celery_app beat  --loglevel=info     # schedules the poll
```
Docker (from repo root): `cp .env.docker.example .env.docker`, fill the Gmail
values, then `docker compose up`.

## 15–19. Connect Gmail from Sentinel
1. Log in as an **admin** (seeded demo: `admin` / `admin123`).
2. Go to **Connected Mailboxes** (`/mailboxes.html`) → **Connect Gmail**.
3. Complete Google consent. You're redirected back with the account shown and
   **Protection: Active**.
4. Click **Test Connection** → confirms the account + that Sentinel's labels
   were created.
5. Click **Scan Now** to run an immediate sync.

## 20. Verify Sentinel's Gmail labels
In Gmail's sidebar you should now see:
`Sentinel/Processed`, `Sentinel/Needs Review`, `Sentinel/Quarantine`,
`Sentinel/Scan Failed`.

## 21–24. Send test emails
- **Legitimate** message → stays in Inbox, gets `Sentinel/Processed`.
- **Medium-risk** (e.g. a mild "please verify" with a link) → gets
  `Sentinel/Needs Review`, stays in Inbox.
- **Phishing** (spoofed brand + shortened link + urgency) → gets
  `Sentinel/Quarantine`, `INBOX` removed (message preserved, not deleted).
Open the detection in **Detections & Incidents** (`/detections.html`).

## 25. Release / confirm
From the incident: **Release** returns it to the Inbox (removes quarantine
label); **Confirm phishing** keeps it quarantined. Both are audit-logged.

## 26. Token refresh
Access tokens expire ~1h; Sentinel refreshes them automatically using the
stored refresh token and re-encrypts the new access token. Nothing to do.

## 27. Polling configuration
`GMAIL_POLL_SECONDS` (default 60) sets how often Beat triggers a sync.
`GMAIL_MAX_MESSAGES_PER_SYNC` bounds each pass. First sync scans
`GMAIL_INITIAL_LOOKBACK_DAYS` (default 1) of recent inbox mail, then goes
incremental via the Gmail History API.

## 28–31. Optional: Pub/Sub push
Only needed if you want near-instant processing instead of polling, and you
have a **public HTTPS** callback.
1. **Create a Pub/Sub topic**: Pub/Sub → Topics → Create (e.g.
   `projects/<proj>/topics/sentinel-gmail`).
2. **Grant Gmail publish rights**: on the topic, add principal
   `gmail-api-push@system.gserviceaccount.com` with role **Pub/Sub Publisher**.
3. **Create a push subscription** whose endpoint is your public webhook:
   `https://<your-app>/api/gmail/pubsub?token=<GOOGLE_PUBSUB_VERIFICATION_TOKEN>`
4. Set env: `GOOGLE_PUBSUB_TOPIC`, `GOOGLE_PUBSUB_VERIFICATION_TOKEN`.
5. In Sentinel, enable push (POST `/api/admin/gmail/watch/start`). The
   `gmail-watch-renew` Beat task re-arms the 7-day watch daily.
If push is unavailable, Sentinel keeps polling — nothing breaks.

## 32–34. Restricted scopes, verification, production security
- `gmail.modify` is a **restricted** scope.
- **Demo/capstone**: External **Testing** mode + test users needs **no**
  verification.
- **Public production**: requires Google **OAuth verification** and a
  **CASA (Cloud Application Security Assessment)** for restricted scopes, plus
  a published privacy policy. Do **not** treat a Testing-mode app as
  production-verified.

---

## Environment variables (reference)
| Var | Required | Purpose |
|-----|----------|---------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | for Gmail | OAuth web client |
| `GOOGLE_OAUTH_REDIRECT_URI` | for Gmail | must match the registered URI |
| `TOKEN_ENCRYPTION_KEY` | for Gmail | encrypts refresh tokens (Fernet) |
| `GMAIL_MONITORING_MODE` | no (polling) | `polling` \| `push` |
| `GMAIL_POLL_SECONDS` | no (60) | poll cadence |
| `GMAIL_MAX_MESSAGES_PER_SYNC` | no (100) | per-pass cap |
| `GMAIL_INITIAL_LOOKBACK_DAYS` | no (1) | first-sync window |
| `GOOGLE_PUBSUB_TOPIC` | push only | Pub/Sub topic name |
| `GOOGLE_PUBSUB_VERIFICATION_TOKEN` | push only | shared webhook token |
| `EML_MAX_BYTES` | no (5 MB) | `.eml` upload cap |
| `UPLOAD_DIR` | no | where `.eml` files are stored (outside static) |
| `IMAP_ENABLED` | no (false) | enable the legacy IMAP poller |

## Troubleshooting
| Symptom | Cause / fix |
|---------|-------------|
| `redirect_uri_mismatch` | The registered redirect URI ≠ `GOOGLE_OAUTH_REDIRECT_URI`. Make them identical (scheme, host, path). |
| `access_blocked` | Account not in **Test users**, or consent screen misconfigured. Add the account. |
| No refresh token / `no_refresh_token` | Revoke Sentinel at <https://myaccount.google.com/permissions> and reconnect (Sentinel forces `prompt=consent`). |
| `invalid_grant` / revoked | User revoked access, or key rotated. **Reconnect** the mailbox. |
| Gmail API disabled | Enable the Gmail API (§2). |
| `insufficient scope` | Reconnect — Sentinel requests `gmail.modify`. |
| Token decryption failure | `TOKEN_ENCRYPTION_KEY` changed or differs across services. Set the same key everywhere, reconnect. |
| Pub/Sub not configured | Expected — polling still works. Leave `GOOGLE_PUBSUB_TOPIC` blank. |
| Webhook unreachable | Push needs a **public HTTPS** endpoint; use polling locally. |
| History ID expired | Handled automatically — Sentinel falls back to a bounded list and re-baselines. |
| Labels missing | Run **Test Connection** or **Scan Now** — labels are created on demand. |
| Celery not running | Start `worker` **and** `beat`; the poll won't fire otherwise. |
| Redis unavailable | Start Redis; Celery broker + rate limiter depend on it. |
| Mailbox paused | Click **Resume** on Connected Mailboxes. |
| Test Connection fails | See the specific error; usually reconnect or re-enable the Gmail API. |
