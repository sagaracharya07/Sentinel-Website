# Sentinel AI — Production Deployment & Readiness

This is the honest production checklist for the Gmail-integrated build. It
separates **what the code/stack already guarantees** from **what you must do
in your own accounts** — nothing here pretends an external step is done.

## What has been verified
- **Container stack** (`docker compose build && up`): web + **PostgreSQL** +
  **Redis** + Celery **worker** + Celery **beat** + minio + mailpit all start
  healthy; `/healthz` and `/readyz` return ok (DB + Redis reachable).
- **Migrations on real Postgres**: `alembic upgrade head` runs clean; all
  tables + the partial unique indexes (`uq_scans_gmail_message`,
  `uq_scans_mailbox_uid`) exist (the `postgresql_where` clauses work, not just
  SQLite).
- **Seeded login** works against Postgres; admin Gmail routes respond
  gracefully when OAuth isn't configured.
- **Background jobs**: beat schedules `gmail-sync`; the worker executes
  `tasks.gmail_sync_task` and returns a safe no-op when no mailbox is
  connected.
- **Automated suite**: 264 tests pass; ruff + format + compile clean.

## What YOU must do (external — cannot be done in code)
1. **Google Cloud + OAuth** — create the project, enable Gmail API, configure
   the consent screen, create a **Web** OAuth client, register the redirect
   URI, add test users. See [GMAIL_SETUP.md](GMAIL_SETUP.md). Put the client
   id/secret + `GOOGLE_OAUTH_REDIRECT_URI` in the deploy env.
2. **`TOKEN_ENCRYPTION_KEY`** — `python crypto.py generate-key`; set the **same
   value** on web, worker, and beat.
3. **Complete the real-Gmail acceptance test** — [GMAIL_ACCEPTANCE_TEST.md](GMAIL_ACCEPTANCE_TEST.md).
   This is the only thing that proves live retrieval/quarantine/release/token
   refresh, and it needs a human to complete Google consent in a browser.
4. **Restricted-scope verification** — `gmail.modify` is restricted. For a
   **public** launch Google requires **OAuth verification + a CASA security
   assessment**, a published privacy policy, and domain verification. Until
   then, run in **Testing** mode with explicit test users. This is a
   multi-week process owned by you and Google.

## Production configuration checklist
- [ ] `SENTINEL_ENV=production` (enforces real secret key + DATABASE_URL; sets
      `SESSION_COOKIE_SECURE`, HSTS).
- [ ] `SENTINEL_SECRET_KEY` — real, unique (Render `generateValue`).
- [ ] `TOKEN_ENCRYPTION_KEY` — same on web/worker/beat.
- [ ] `DATABASE_URL` — managed Postgres.
- [ ] `REDIS_URL` — managed Redis (broker + rate-limit store).
- [ ] `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_OAUTH_REDIRECT_URI`.
- [ ] TLS in front of the app (Render terminates TLS; the OAuth redirect URI
      must be `https://`).
- [ ] `IMAP_ENABLED` unset/false (Gmail is primary).
- [ ] Object storage (`ARTIFACT_STORE_*`) so retrains propagate across services.
- [ ] Outbound email (`MAIL_*`) for verification/reset.
- [ ] (Optional push) `GOOGLE_PUBSUB_TOPIC` + `GOOGLE_PUBSUB_AUDIENCE`
      (OIDC) — with a public HTTPS webhook and the topic granting Gmail
      publish rights.
- [ ] `SENTRY_DSN` (optional) for error tracking on all three services.

## Security posture (implemented)
- Refresh tokens encrypted at rest (Fernet); never logged / returned /
  templated. OAuth `state` validated (connection-CSRF). CSRF on all
  browser-facing POSTs; the Pub/Sub webhook is fail-closed (OIDC token or
  shared secret) and CSRF-exempt only because it's machine-to-machine.
- RBAC: all mailbox/detection/quarantine/release routes are admin-only;
  users see only their own scans/reports.
- `.eml` uploads validated (extension/size), filenames sanitised, stored
  outside the static tree, never served, never executed; HTML never rendered;
  no URL is ever fetched (no SSRF).
- Audit logging on all sensitive actions; rate limiting on auth/OAuth/upload;
  security headers + CSP applied on every response.

## Not production-ready until
- The real-Gmail acceptance test passes against a live account, **and**
- (for a public launch) Google restricted-scope verification + CASA complete.
Running in Testing mode for an internal/demo deployment is fine and needs
neither.
