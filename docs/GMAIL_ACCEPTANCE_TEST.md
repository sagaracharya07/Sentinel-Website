# Sentinel AI — Real Gmail Acceptance Test (manual)

> **This is a manual procedure that requires a real Google account and the
> external setup in [GMAIL_SETUP.md](GMAIL_SETUP.md).** The automated test
> suite (`pytest`) uses mocks and a fake Gmail service — it never touches a
> real account. **Nothing in this checklist has been executed automatically;**
> record your own results in the "Result" column when you run it.
>
> Use a **throwaway test Gmail account**, not a personal one.

## Preconditions
- Google Cloud project with Gmail API enabled, OAuth web client, redirect URI
  registered, test user added (see GMAIL_SETUP.md §1–8).
- `.env` populated incl. `TOKEN_ENCRYPTION_KEY`, `GOOGLE_CLIENT_ID/SECRET`,
  `GOOGLE_OAUTH_REDIRECT_URI`.
- Running: web + Redis + Celery **worker** + Celery **beat**, DB migrated.

## Procedure

| # | Step | Expected | Result |
|---|------|----------|--------|
| 1 | Log in as admin (`admin`/`admin123`) | Admin console reachable | ☐ |
| 2 | Open **Connected Mailboxes** | Page loads, "Not connected" | ☐ |
| 3 | Click **Connect Gmail** | Redirect to Google consent | ☐ |
| 4 | Complete Google OAuth | Redirect back to Sentinel | ☐ |
| 5 | Connected account shown | Correct Gmail address displayed | ☐ |
| 6 | Protection status | **Active** | ☐ |
| 7 | Check Gmail labels | `Sentinel/Processed`, `Needs Review`, `Quarantine`, `Scan Failed` exist | ☐ |
| 8 | **Test Connection** | OK, profile + labels ready | ☐ |
| 9 | Send a **legitimate** email to the mailbox | Arrives in Inbox | ☐ |
| 10 | Wait for sync / click **Scan Now** | Sentinel retrieves it | ☐ |
| 11 | Legitimate message disposition | Stays in **Inbox** | ☐ |
| 12 | Processed label | `Sentinel/Processed` applied | ☐ |
| 13 | Send a **medium-risk** email (mild verify + link) | Arrives | ☐ |
| 14 | After sync | `Sentinel/Needs Review` applied | ☐ |
| 15 | Needs-review disposition | Remains available in Inbox | ☐ |
| 16 | Send a **phishing** email (spoofed brand + shortened link + urgency) | Arrives | ☐ |
| 17 | After sync | `Sentinel/Quarantine` applied | ☐ |
| 18 | Phishing disposition | `INBOX` removed (not deleted) | ☐ |
| 19 | Detection in Sentinel | Appears in Detections & Incidents | ☐ |
| 20 | Incident details | Headers, findings (SPF/DKIM/DMARC, links), verdict shown | ☐ |
| 21 | **Release** the quarantined message | Returns to Inbox | ☐ |
| 22 | Gmail state after release | Back in Inbox, quarantine label removed | ☐ |
| 23 | **Confirm phishing** on another quarantined message | Stays quarantined | ☐ |
| 24 | Message after confirm | Remains out of Inbox | ☐ |
| 25 | Audit log | Connect/quarantine/release/confirm all recorded | ☐ |
| 26 | As a **normal user**, upload a real `.eml` (`/report.html`) | Accepted | ☐ |
| 27 | Sentinel analyses it | Verdict + findings shown | ☐ |
| 28 | Admin reviews the report (`/detections.html` → Reported) | Report visible | ☐ |
| 29 | User sees final verdict (`/report.html` My Reports) | Admin verdict shown | ☐ |
| 30 | Run **Scan Now** twice | No duplicate detections | ☐ |
| 31 | Wait > 1h, trigger a sync | Token auto-refreshes, sync still works | ☐ |
| 32 | Send a malformed email, then a normal one | Malformed doesn't stop the normal one; both handled | ☐ |
| 33 | Click **Pause** | Automatic scanning stops | ☐ |
| 34 | Click **Resume** | Automatic scanning restarts | ☐ |

### Optional (push mode)
| # | Step | Expected | Result |
|---|------|----------|--------|
| P1 | Configure Pub/Sub (GMAIL_SETUP §28–31) + enable push | `monitoring_mode=push` | ☐ |
| P2 | Send a message | Webhook fires → near-instant processing | ☐ |
| P3 | Leave running > 1 day | `gmail-watch-renew` re-arms the watch | ☐ |

**Label any step you did not actually perform.** Do not report real-Gmail
verification as passed without evidence (screenshots / Gmail label state /
Sentinel audit-log entries).
