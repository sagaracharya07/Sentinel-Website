# Sentinel AI — AI Phishing Detection Platform

A working implementation of the platform described in the NIT3003 capstone
proposal: a trained machine-learning classifier sitting behind a real
backend and database, with a front-end for scanning email and an admin
console for reviewing detections, correcting them, and retraining the model.

This build **replaces** an earlier front-end-only demo that used a
hand-written JavaScript keyword scorer and the browser's `localStorage`
in place of a real model and database. That demo is gone; every piece
described below is real and running.

---

## 1. What's actually in here

| Layer | Technology | Status |
|---|---|---|
| Front-end | Static HTML/CSS/JS (`site/`) + Jinja2 templates (`backend/templates/`) | Same visual design, calling a real API |
| Server | Flask (`backend/app.py`) | Real REST API, session-based auth, role checks, CSRF-protected |
| ML model | scikit-learn Random Forest + TF-IDF (`backend/ml/`) | Trained on ~37,700 real labelled emails |
| Database | SQLite (local dev) or PostgreSQL (Docker/Render) via SQLAlchemy + Alembic migrations | Schema managed by `alembic upgrade head`, not `db.create_all()` |
| Background jobs | Celery worker + Celery Beat, Redis as broker | Mailbox polling, retraining, and the privacy-purge sweep run here |
| Model artifacts | Local `backend/ml/artifacts/<version>/`, optionally S3/MinIO-compatible object storage | Lets web/worker/beat share the active model when they're separate processes/hosts |
| Auth | Werkzeug password hashing + Flask sessions + CSRF tokens | Two seeded demo accounts (see below), plus self-serve registration with email verification |

## 2. Quick start

### Local (SQLite, no Docker/Postgres/Redis needed)

```bash
cd backend
pip install -r requirements.txt
python3 app.py
```

Then open **http://localhost:5000** in a browser. The database, demo
accounts, and demo scan history are created automatically the first time
`app.py` runs (see `ensure_seed_data()` in `app.py` / `seed_db.py`). This
mode has no Redis, so Celery-backed background jobs (mailbox polling,
retraining) don't run automatically — trigger them manually from the admin
console instead, or run `celery -A celery_app worker` / `celery -A
celery_app beat` alongside `python3 app.py` if you want them live.

### Full stack (PostgreSQL + Redis + Celery + MinIO, via Docker Compose)

```bash
docker compose build
docker compose up
```

Brings up Postgres, Redis, MinIO (S3-compatible model artifact storage),
Mailpit (a local SMTP catcher so verification/reset emails are visible
without real mail credentials, at http://localhost:8025), the Flask web
process, a Celery worker, and Celery Beat. Migrations and demo seeding run
automatically before the web process starts (see `backend/Dockerfile`).
Open **http://localhost:5000** once `docker compose up` reports the `web`
service healthy.

**Demo accounts** (seeded automatically, shown on the login screen too):

| Username | Password | Role | Access |
|---|---|---|---|
| `admin` | `admin123` | admin | `/admin.html` — quarantine review, model info, retraining |
| `user`  | `user123`  | user  | `/scan.html` — scan emails, submit feedback |

## 3. Connecting a real mailbox

**Gmail via Google OAuth is the primary integration.** An administrator
connects a Gmail mailbox from the website (**Connected Mailboxes** →
**Connect Gmail**); Sentinel stores an **encrypted refresh token** (never a
password), creates its Gmail labels, and then automatically retrieves, fully
parses (MIME, SPF/DKIM/DMARC, links, attachments), classifies, and labels
incoming mail — **quarantine = add `Sentinel/Quarantine` + remove `INBOX`**
(never a delete), **release = the reverse**. Monitoring is **polling by
default** (Celery Beat → `tasks.gmail_sync_task`, incremental via the Gmail
History API) with **optional Pub/Sub push**. Full setup:
**[docs/GMAIL_SETUP.md](docs/GMAIL_SETUP.md)**; manual acceptance test:
**[docs/GMAIL_ACCEPTANCE_TEST.md](docs/GMAIL_ACCEPTANCE_TEST.md)**.

Two secondary paths also exist:

- **Employee `.eml` reporting** (`/report.html`) — a user uploads an original
  message; it runs the **same full analysis pipeline** as Gmail mail and
  creates a report an admin reviews (`/detections.html`).
- **Quick Analysis** (`scan.html`) — paste sender/subject/body for a fast
  text-only verdict (no headers/auth/links/attachments). Useful for testing
  and the feedback loop, not a "production" path.

### Legacy IMAP (dev/fallback, disabled by default)

The older **IMAP-over-SSL** integration is retained as a tested legacy/dev
fallback but is **off by default** — set `IMAP_ENABLED=true` (plus the
`MAILBOX_*` env vars) to schedule its poller. It is not used when Gmail is
connected, so the two never double-process the same mailbox. Sentinel does
**not** claim Outlook/Yahoo/Microsoft 365 integration; the IMAP fallback can
technically connect to any IMAP-over-SSL server with an app password, and
Microsoft Graph OAuth is a possible **future** enhancement, not implemented.

<details><summary>Legacy IMAP details</summary>

   A Celery Beat job (`tasks.mailbox_sync_task`,
   `backend/celery_app.py`/`backend/tasks.py`) connects to a real mailbox
   over IMAP-over-SSL, pulls new mail automatically every
   `MAILBOX_POLL_SECONDS` (default 45s), classifies each message with the
   same trained model, and takes a real action based on the three-state
   decision below:
   - **Phishing (High risk) → moved into a real `Sentinel-Quarantine` folder**
     in that mailbox (created automatically if it doesn't exist).
   - **Needs Review (Medium risk) → flagged** (`\Flagged`) in place, left in
     the inbox for a human to look at — never silently quarantined or
     silently dropped to Legitimate.
   - **Legitimate (Low risk) → left alone.**

   The same code path (`mailbox/sync.py`) backs both the scheduled Celery job
   and the admin console's manual **"Sync now"** button, and a DB-backed lock
   (`MailboxStatus.sync_in_progress`) stops the two from ever running
   concurrently against the same mailbox. A partial unique index on
   `Scan.mailbox_uid` is the backstop that guarantees no message is ever
   recorded twice even if that lock is somehow bypassed.

   Releasing a false positive from the admin console **moves the real email
   back to the inbox** (looked up by its stable `Message-ID` header, since IMAP
   UIDs aren't stable across folders) — quarantine is a genuine, reversible
   mailbox action, not just a database flag.

   **Known limitation:** the uniqueness key is IMAP UID alone (scoped to
   `source='mailbox'`), not `(account, folder, UIDVALIDITY, UID)`. IMAP UIDs
   are only guaranteed unique within one folder for one UIDVALIDITY epoch —
   fine as long as there's exactly one configured mailbox account and its
   folder isn't recreated, which holds for this single-mailbox prototype, but
   full UIDVALIDITY tracking would be needed before trusting this across
   multiple accounts or a recreated folder.

### Setup

```bash
cd backend
cp .env.example .env
# edit .env with your mailbox host/username/app-password — see the
# comments in .env.example for Gmail / Outlook / Yahoo specifics
python3 app.py
```

Use a **throwaway test mailbox** while you're getting this working, not your
primary account — and always use an **app password**, never your real login
password (App Passwords require 2-Step Verification to be turned on; Gmail:
https://myaccount.google.com/apppasswords). Connections are always
IMAP-over-SSL (port 993) — there is no plaintext-IMAP option to configure.

The admin console's **"Live mailbox connection"** panel shows real connection
status (host, account, last sync time, message counts, last error) and has
**Test connection** / **Sync now** buttons. If `.env` isn't configured, it
says so plainly instead of pretending to be connected.

### What this doesn't do (by design)

- **No permanent deletion** — quarantine is always a folder move, reversible
  from any real mail client at any time, not just from this admin console.
- **No IMAP IDLE (push)** — it polls on an interval rather than getting
  instant push notifications. IDLE is the natural next upgrade (see Section 15).
- **Single mailbox, not per-user inboxes** — one account is monitored
  (representing "the organisation's protected mailbox"), matching the
  proposal's own framing of the platform sitting in front of a mail server
  rather than inside every individual user's inbox.

</details>

## 4. The ML model

`backend/ml/prepare_data.py` builds `backend/data/combined_dataset.csv`
from four public, citable corpora (see `backend/data/DATASET_SOURCES.md`):
CEAS 2008, Apache SpamAssassin, the Nazario phishing corpus, the Nigerian
/ "419" fraud corpus, and a portion of the Enron corpus (for realistic
short, casual *legitimate* business email, which pure phishing corpora
under-represent).

`backend/ml/train.py` builds two feature families for a `RandomForestClassifier`:

1. **TF-IDF** over the subject + body text (1-2 grams, 3,500 features).
2. **Engineered signals** mirroring the proposal's pseudocode (Section
   6.4-6.5): urgency-language hits, credential-request hits, generic
   greetings, suspicious/shortened/raw-IP URLs, sender/brand-domain
   mismatch, formatting anomalies, message length. These are what get
   surfaced back to the user as the "detected signals" explanation —
   the model's TF-IDF half isn't individually explainable, so the
   engineered half carries the explainability requirement (FR-FE-05).

### Three-state decision logic

`ml/infer.decide()` turns the model's raw phishing probability into an
operational verdict using three bands, not a single 50% cutoff:

| Phishing probability | Classification | Risk level | Mailbox action |
|---|---|---|---|
| ≥ 75% | **Phishing** | High | Quarantine |
| 50%–74% | **Needs Review** | Medium | Flag for analyst review (not quarantined) |
| < 50% | **Legitimate** | Low | None |

A flat 50% cutoff meant a message the model was only ~63% sure about got
labelled "Phishing" with the same weight as one at 99% — this splits that
middle band out instead of silently rounding it either direction.

### Probability vs. confidence

The API exposes both, and they are not the same number:

- **`phishing_probability`** — the model's raw P(phishing) for this message.
- **`prediction_confidence`** — how sure the model is of *whichever* label it
  picked: `max(phishing_probability, 1 - phishing_probability)`. A message
  at 5% phishing probability is 95%-confidently legitimate, not "5%
  confident" — reporting the raw phishing probability as "confidence" (as
  an earlier version of this API did, under a field literally named
  `confidence_score`) was misleading for anything below the Phishing
  threshold.

For backward compatibility, `confidence_score` is still present in scan
records and the API response and still means the same thing it always did
(phishing probability) — new code should read `phishing_probability`
instead; `confidence_score` is kept so existing seeded/historical rows and
any external consumer reading that field don't break.

**Current model performance** (held-out 20% test split, `backend/ml/artifacts/v1/metrics.json`):

| Metric | Result | Proposal target (NFR-Accuracy) |
|---|---|---|
| Accuracy | 96.1% | — |
| Precision | 94.9% | ≥ 90% ✅ |
| Recall | 96.8% | — |
| F1 | 95.8% | — |
| False positive rate | 4.5% | ≤ 10% ✅ |
| False negative rate | 3.3% | ≤ 10% ✅ |

These are real numbers from a real train/test split — run
`python3 -m ml.train` yourself to reproduce them (takes about a minute).

## 5. Retraining loop (UC-07)

1. A user or admin corrects a scan's label (feedback buttons on `scan.html`,
   or Release/Confirm on `admin.html`) → stored in the `feedback` table.
2. An admin clicks **"Retrain with new feedback"** on `admin.html` (or
   `POST /api/admin/retrain`) — this runs on a Celery worker, not the
   request thread, since training takes about a minute.
3. `ml/train.py` folds all not-yet-used feedback rows into the training
   set, trains a new versioned model (`v2`, `v3`, …), and writes fresh
   metrics — this produces a **reviewable candidate**, it does **not**
   change what's live. `ModelVersion.is_current` stays `False`.
4. An admin reviews the new version's metrics next to the current one in
   the "Version history" list and explicitly clicks **Promote** (`POST
   /api/admin/model-version/<version>/promote`) to make it live —
   `ml.infer.promote()` hot-swaps the in-memory model with no restart
   needed. **Rollback is the same action**: promoting an older,
   previously-live version *is* the rollback mechanism, there's no
   separate rollback endpoint.
5. Every past version and its metrics stay in the `model_versions` table
   so the retraining history is auditable, not just the latest number.

## 6. Data minimisation / retention (FR-DB-05)

A background thread (`purge_loop` in `app.py`) runs every 10 minutes and
redacts (`body = NULL`) any scan older than 24 hours, replacing it with a
placeholder string in the API response. This is a real, running policy,
not a comment in a report — seed data intentionally includes scans older
than 24h so you can see this happen immediately on first run (check the
`audit_log` table or `/api/admin/audit-log` for `privacy_purge` entries).

## 7. Security — what's real vs. what's a deployment concern

- **Real:** password hashing (Werkzeug/PBKDF2), server-side session
  cookies (HttpOnly, SameSite=Lax), CSRF protection (Flask-WTF
  `CSRFProtect`) on every state-changing route — the frontend fetches a
  token from `GET /api/csrf-token` and sends it back as `X-CSRFToken` on
  every POST (see `site/js/api.js`), role-based authorization enforced on
  *every* API route (not just hidden client-side, and not just an
  opt-in query parameter — `/api/history` and `/api/stats` scope to the
  logged-in user's own scans unless they're an admin, unconditionally),
  input length limits, security response headers
  (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`).
- **Deployment concern, not implemented here:** TLS/HTTPS termination.
  Flask's built-in dev server speaks plain HTTP; in any real deployment
  this app would sit behind a reverse proxy (nginx, Caddy) or a platform
  (Render, Fly.io, etc.) that terminates TLS, which is the standard
  pattern for Flask apps and is what the proposal's "TLS 1.2+ HTTPS"
  requirement assumes at the infrastructure layer. This is called out
  explicitly rather than faked with a self-signed cert.

## 8. Design deviation from the proposal wireframe (documented, not accidental)

The proposal's Screen 1 wireframe shows a client-side "Role: (•) User (•)
Admin" selector on the login form. That was **not implemented as drawn**
on purpose: letting the client choose its own role would make role-based
access control meaningless (anyone could tick "Admin"). Instead, role is
an attribute of the authenticated account and is enforced server-side on
every request (`@admin_required` in `auth.py`); the login screen shows a
demo-credentials hint instead of a role toggle. This is flagged here so
it reads as a considered security decision if a marker compares the build
against the wireframe.

## 9. Project structure

```
site/               static assets served by Flask (CSS/JS only — pages are now Jinja2 templates)
  css/styles.css       shared styling (chips, forms, tables, layout)
  js/api.js            fetch() wrapper for the backend API — attaches CSRF token to every POST
  js/auth-guard.js      client-side login/role redirect helper
  js/classifier.js      presentation-only helpers (highlight/escape, verdict copy, finding categories)
  js/scan.js, admin.js, landing.js, hud.js, lightning.js, account.js, login.js, signup.js, ...

backend/
  app.py               Flask app + all API routes, CSRF setup, security headers, health endpoints
  models.py            SQLAlchemy models (Scan, Feedback, ModelVersion, User, AuditLog, MailboxStatus)
  auth.py               password hashing, session decorators, audit logging
  celery_app.py         Celery app + Beat schedule (mailbox sync, privacy purge)
  tasks.py               Celery tasks (mailbox sync, retrain, purge)
  db_config.py           resolves SQLite (local dev) vs. Postgres (DATABASE_URL) — shared by app.py + Alembic
  seed_db.py, seed_startup.py   demo accounts + demo scan data, run once before gunicorn starts
  logging_config.py, monitoring.py   structured logging + optional Sentry integration
  requirements.txt, requirements-dev.txt
  .env.example          mailbox/mail/secret-key credential template — copy to .env and fill in
  Dockerfile             single image, reused for web/worker/beat roles (see docker-compose.yml)
  templates/              Jinja2 page templates (index, login, scan, admin, etc.)
  migrations/versions/    Alembic migration chain (SQLite + Postgres compatible via batch_alter_table)
  mailbox/
    imap_client.py       real IMAP-over-SSL connect/fetch/quarantine/unquarantine/flag
    sync.py                bridges the mailbox to the ML pipeline + DB; DB-backed sync lock lives here
  ml/
    features.py          shared feature extraction (used by training AND inference)
    prepare_data.py       builds the combined training dataset
    train.py               trains + versions the Random Forest model
    infer.py                loads the current model, classifies a single email (three-state decide())
    artifact_store.py      optional S3/MinIO-compatible artifact sync (no-op if unconfigured)
    artifacts/<version>/   saved model + vectorizer + scaler + metrics per version
  mail/
    email_client.py       outbound SMTP for verification/reset/contact emails (console fallback if unset)
  data/
    combined_dataset.csv   the actual training data
    DATASET_SOURCES.md     citations for the four source corpora
  tests/                   pytest suite (auth, scan, mailbox sync, model governance, CSRF, health, ...)
  instance/
    sentinel.db            local SQLite database (created on first run; not used when DATABASE_URL is set)
```

## 10. API reference

**Admin review workflow:** the admin console's "Scan & quarantine log" panel has six filter tabs (All / Needs review / Quarantined / Flagged / Delivered / Released) plus a live "N item(s) awaiting review" count (quarantined + flagged, i.e. not yet released or confirmed). "Needs review" filters by classification; "Released" isn't a status of its own (a release just returns a scan to `Delivered`) so it's identified by the notes text `admin_action()`'s release branch sets — both are backed by real `/api/history?classification=`/`?released=true` query params, not just client-side display tricks. Every scan row is keyboard-operable (not just clickable) and opens the same detail modal with Release/Confirm/Escalate actions, unchanged from before.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/healthz` | — | liveness (process is up) |
| GET | `/readyz` | — | readiness (DB + Redis reachable) |
| GET | `/api/csrf-token` | — | fetch a CSRF token; required as `X-CSRFToken` on every POST below |
| POST | `/api/auth/login` | — | log in, sets session cookie |
| POST | `/api/auth/register` | — | self-serve signup (role always `user`, email verification required) |
| POST | `/api/auth/logout` | — | clear session |
| GET | `/api/auth/me` | session | current user info |
| POST | `/api/auth/change-password` | user | change own password |
| GET | `/api/public/demo-scan` | — | canned example through the real model (homepage) |
| POST | `/api/scan` | user | classify a manually-pasted email, persist it |
| GET | `/api/history` | user | list own scans (all scans if admin); `?status=`, `?classification=`, `?released=true`, `?limit=` |
| GET | `/api/scan/<id>` | user | single scan detail (own scans only, unless admin) |
| GET | `/api/stats` | user | aggregate counts (`total`/`phishing`/`needs_review`/`legitimate`/`quarantined`/`flagged`/`pending_review`), `avg_phishing_probability` and `avg_prediction_confidence` (two distinct numbers, not one ambiguous `avg_confidence`) — own scans only, unless admin (`scope` field says which) |
| POST | `/api/feedback` | user | correct a scan's label (own scans only, unless admin — 403 otherwise) |
| POST | `/api/admin/action` | admin | release (real un-quarantine) / confirm / escalate |
| GET | `/api/admin/model-info` | admin | current + historical model metrics |
| POST | `/api/admin/retrain` | admin | fold in feedback, train a new candidate model (does not go live) |
| POST | `/api/admin/model-version/<version>/promote` | admin | make a version live — also the rollback mechanism |
| GET | `/api/admin/audit-log` | admin | recent audit trail |
| POST | `/api/admin/reset-demo-data` | admin | wipe and reseed demo scans |
| GET | `/api/admin/mailbox-status` | admin | live connection/sync status |
| POST | `/api/admin/mailbox-test` | admin | test the IMAP connection right now |
| POST | `/api/admin/mailbox-sync` | admin | trigger an immediate sync (same code path as the Celery Beat job) |

## 11. Backing up and rolling back

**Before running any migration against a database you care about** (the seeded local SQLite file, or a real Postgres instance), back it up:

```bash
# SQLite (local dev)
cp backend/instance/sentinel.db backend/instance/sentinel.db.bak-$(date +%Y%m%d)

# Postgres (Docker/Render)
docker compose exec db pg_dump -U sentinel sentinel > sentinel_backup_$(date +%Y%m%d).sql
```

To roll back a migration:

```bash
cd backend
alembic current            # see what revision you're on
alembic downgrade -1        # step back one migration
# or: alembic downgrade <revision_id>   # jump to a specific revision
```

Every migration in this project (`backend/migrations/versions/`) has a real `downgrade()`, not a stub -- both new-column migrations (`08b35ecd1585`, `3bf198b6ab98`) drop exactly the columns/indexes they added, nothing else. None of them are destructive on `upgrade()` (no dropped columns, no data rewrites) -- see each migration file's own docstring for why the specific approach taken (e.g. `batch_alter_table` for SQLite, `server_default` on new NOT NULL columns) was chosen to avoid breaking existing rows.

If a downgrade would lose data that only exists because of the newer schema (there isn't one of those in this project today, but if a future migration adds one), restore from the backup above instead of downgrading through it.

## 12. Testing & deployment verification

```bash
cd backend
pip install -r requirements-dev.txt
pytest -v                  # unit + integration tests (SQLite, isolated temp DB)
ruff check .                # lint
ruff format --check .       # formatting (not currently enforced clean — see below)
python -m compileall .       # syntax check
```

CI (`.github/workflows/ci.yml`) additionally runs `alembic upgrade head`
against a real Postgres service container, so the migration chain is
checked against both SQLite (implicitly, via the test suite's DB fixture)
and Postgres (explicitly, in CI) — not just one dialect.

**Python version:** both `backend/Dockerfile` and CI pin `python:3.14`.
This was flagged during the Phase 1 audit as an unverified combination
with `scikit-learn`/`pandas`/`scipy`/`psycopg2-binary`, since 3.14 postdates
this project's original knowledge base. It has since been verified
empirically on this codebase: `pip install -r requirements.txt` (including
`psycopg2-binary`, which ships pre-built wheels tied to a specific CPython
ABI and is the most likely package to lag a new Python release) completed
without needing to compile anything from source, and the full test suite
(82 tests) passes under Python 3.14.6. Kept at 3.14 rather than downgraded
to 3.12 on that evidence, though the *containerized* build/run (`docker
compose build && docker compose up`) has not been exercised end-to-end in
this environment — Docker Desktop's engine did not come up here. `docker
compose config` (static validation of `docker-compose.yml`) does pass.
Before a real submission demo, run `docker compose build && docker compose
up` once yourself and confirm the `web` service reaches healthy — don't
take this README's word for it beyond what's stated above.

## 13. Accessibility

A focused pass (not a full audit) on `scan.html` and `admin.html`, since those are the two pages with real dynamic content:

- **Fixed:** admin console's scan-log table rows were mouse-only (a bare `<tr>` click handler, no keyboard path at all) -- they're now `tabindex="0" role="button"` with an Enter/Space handler, so every scan is reachable and operable from the keyboard, not just a mouse.
- **Fixed:** the scan-detail modal didn't manage focus -- opening it left focus behind on the page, and closing it didn't return focus anywhere. It now moves focus to the modal's close button on open, restores focus to whichever row/control opened it on close, and traps Tab/Shift+Tab inside the dialog while it's open (verified live: Shift+Tab from the first focusable element wraps to the last, and vice versa).
- **Fixed:** `--safe` (a blue, `#4C6FFF`) measured ~4.0:1 contrast as literal text color on the dark background -- just under the WCAG AA 4.5:1 minimum for normal text. Added `--safe-text` (`#8FA5FF`, ~7.2:1) and switched every place `--safe` was used as text (chips, success messages, status pills, stat cards) to it, leaving `--safe` itself unchanged for backgrounds/dots/borders where the ratio doesn't apply.
- **Already in place, verified still correct:** `aria-live`/`role="status"`/`role="alert"` on error messages, the processing spinner, feedback confirmation, mailbox error banner, and toast; proper `<label for>` on every form input; a global `:focus-visible` outline (not suppressed anywhere); `prefers-reduced-motion` handling for the animated backgrounds; the scan-log and admin tables wrap in `overflow-x:auto` rather than causing page-level horizontal scroll on mobile (checked at a 375px viewport).
- **Requires manual verification, not done here:** testing with an actual screen reader (NVDA/JAWS/VoiceOver) rather than the accessibility-tree inspection used above; an exhaustive contrast audit of every color pairing on every page (only the confirmed `--safe` issue was fixed); testing with voice-control/switch-access software.

## 14. Known limitations (be upfront about these in your report/demo)

- **The text model can produce false positives/negatives.** Precision and
  recall are both in the mid-to-high 90s (Section 4), not 100% — the
  three-state "Needs Review" band exists specifically because
  medium-confidence results should get a human look, not an automatic
  verdict either way.
- **Medium-confidence ("Needs Review") results require human review** —
  they are flagged, not quarantined and not silently cleared, by design.
- **No full SPF/DKIM/DMARC authentication analysis** — manual scans are
  text-only (sender/subject/body you paste), and even live mailbox scans
  don't independently re-verify sender authentication results.
- **Attachments are not analysed** — neither manual nor live mailbox scans
  inspect attachment content.
- **No external threat-intelligence API integration** — detection is the
  trained model + engineered text/link signals only, not a blocklist/feed
  lookup against a third-party reputation service.
- **Single monitored mailbox account**, not per-user inboxes or multiple
  accounts — represents "the organisation's protected mailbox" sitting in
  front of a mail server. The mailbox-message uniqueness key is also
  UID-only (see Section 3's known limitation on IMAP UIDVALIDITY).
- **IMAP polling (every 45s by default), not IMAP IDLE** (instant push) — a
  reasonable simplification for a capstone build, and a clearly named
  upgrade path (see the suggestions below) rather than a hidden gap.
- **Model evaluation is based on this project's own held-out test
  partition** (Section 4) — a real train/test split, reproducible by
  running `ml/train.py` yourself, but not an independent or
  industry-benchmark evaluation. Reported accuracy is not a guarantee of
  real-world performance on traffic the model has never seen.
- No real SMTP integration for *sending* mail (quarantine notices, etc.) —
  not in scope; the platform reads and reorganises mail, it never sends any.
- Retraining uses whatever admin-confirmed feedback exists; with only a
  handful of corrections the metric movement between versions will be
  small — that's expected and worth explaining rather than hiding.
- Pricing tiers (`pricing.html`) describe intended commercial packaging,
  not an enforced restriction — this build has no billing system, so every
  account currently has access to mailbox monitoring, quarantine, and the
  admin console regardless of which tier they'd notionally be on.

## 15. Suggestions for further upgrade (roughly ordered by effort vs. payoff)

**Small, high-payoff (do these if you have any time left):**
- **Multiple monitored mailboxes** — extend `MailboxConfig` to a list loaded
  from a small `mailbox_accounts` table instead of one `.env` block, so the
  platform can protect more than one inbox. Mostly a matter of looping the
  existing `sync_mailbox()` per account; the hard part (fetch/classify/
  quarantine) is already written.
- **CSV/PDF export of the admin scan log** — markers like being able to open
  a spreadsheet of results; `pandas.DataFrame(...).to_csv()` on the same
  query `/api/history` already runs gets you 90% of the way there.
- **Confusion matrix visual on the model panel** — you already compute
  `tn/fp/fn/tp` in `metrics.json`; a small 2×2 grid on `admin.html` next to
  the metric numbers makes the "how good is the model, really" story land
  better visually than four numbers alone.

**Medium effort, meaningfully closes remaining gaps:**
- **IMAP IDLE instead of polling** — `imap_tools`'s `MailBox.idle` context
  lets the server push new-mail notifications instantly instead of waiting
  up to 45s. This is the "real-time" upgrade if a marker specifically probes
  the word "real-time" in your proposal.
- **Rate limiting on `/api/auth/login`** — a few failed attempts should
  slow down/lock out; right now it's unlimited, which is a real (if minor)
  security gap for anything beyond an academic demo.
- **HTTPS in front of Flask** — spin up a simple `nginx` config with a
  self-signed cert for your demo environment (not needed for `localhost`
  testing, but shows you understand the actual deployment step rather than
  just writing "TLS 1.2+" in a requirements table).

**Larger, "nice to have if this becomes more than a capstone":**
- **OAuth2 for Gmail/Outlook instead of app passwords** — app passwords are
  fine for an academic build but a real product wouldn't ask users to
  generate one; OAuth2 + Gmail API (or Microsoft Graph) is the production
  path, at the cost of a much more involved auth flow.
- **A proper WSGI server (gunicorn/waitress) instead of Flask's dev server**
  — one line in a `Procfile` or a small `wsgi.py`, but worth doing before
  calling anything "production."
- **Deep-learning model comparison** — your slides already list this as a
  "Future Enhancement." If you want a stronger results section, training a
  simple LSTM or fine-tuned DistilBERT on the same dataset and comparing
  precision/recall against the Random Forest would be a genuinely
  interesting appendix, not just a slide bullet.
