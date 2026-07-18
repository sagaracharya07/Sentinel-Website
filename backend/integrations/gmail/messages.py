"""
Gmail message retrieval, label modification, and quarantine/release actions.

Quarantine/release are expressed as *label operations*, which is what makes
them reversible and non-destructive:
    quarantine -> add Sentinel/Quarantine, remove INBOX   (message preserved)
    release    -> add INBOX, remove Sentinel/Quarantine + Needs Review

Gmail's users.messages.modify is idempotent: adding a label already present,
or removing one already absent, is a no-op, not an error. So repeated
quarantine/release calls converge on the same state rather than corrupting it.

extract_basic() pulls just enough (sender/subject/plain body) to run the
existing classifier during Checkpoint 2. Checkpoint 3 replaces it with a full
MIME parser + structured security analysis; the sync pipeline calls one
function, so that swap is localised.
"""

import base64
import logging

from . import client

logger = logging.getLogger(__name__)

INBOX_LABEL_ID = "INBOX"


# ---------------------------------------------------------------------------
# retrieval
# ---------------------------------------------------------------------------
def get_profile(service) -> dict:
    """Mailbox identity + current historyId. Used by 'Test connection' and to
    baseline incremental sync."""
    return client.execute(service.users().getProfile(userId="me"))


def get_message(service, message_id: str, msg_format: str = "full") -> dict:
    return client.execute(
        service.users().messages().get(userId="me", id=message_id, format=msg_format)
    )


def get_raw(service, message_id: str) -> dict:
    """Fetch a message in 'raw' format -- returns the base64url RFC822 bytes
    (in the 'raw' field) plus id/threadId/historyId. This is what the full
    MIME parser (parser.py) consumes, shared with .eml uploads."""
    return client.execute(
        service.users().messages().get(userId="me", id=message_id, format="raw")
    )


def list_message_ids(
    service, max_results: int = 100, query: str | None = None
) -> list[dict]:
    """List up to max_results messages (newest first), as [{id, threadId}].
    `query` is a Gmail search string (e.g. 'newer_than:2d') used for the
    bounded fallback when no/expired history id is available."""
    out: list[dict] = []
    page_token = None
    while len(out) < max_results:
        req = (
            service.users()
            .messages()
            .list(
                userId="me",
                maxResults=min(100, max_results - len(out)),
                q=query,
                pageToken=page_token,
            )
        )
        resp = client.execute(req)
        out.extend(resp.get("messages", []) or [])
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return out[:max_results]


def list_history(service, start_history_id: str, max_results: int = 100):
    """Incremental change list since start_history_id. Returns
    (added_message_ids, latest_history_id). Raises GmailHistoryExpiredError
    (via client.execute history=True) if the id is too old to use."""
    added: list[str] = []
    seen: set[str] = set()
    page_token = None
    latest = start_history_id
    while True:
        req = (
            service.users()
            .history()
            .list(
                userId="me",
                startHistoryId=start_history_id,
                historyTypes=["messageAdded"],
                maxResults=max_results,
                pageToken=page_token,
            )
        )
        resp = client.execute(req, history=True)
        latest = resp.get("historyId", latest)
        for record in resp.get("history", []) or []:
            for added_rec in record.get("messagesAdded", []) or []:
                msg = added_rec.get("message", {})
                mid = msg.get("id")
                # Skip messages that never hit the inbox (drafts/sent).
                labels = msg.get("labelIds", [])
                if mid and mid not in seen and INBOX_LABEL_ID in labels:
                    seen.add(mid)
                    added.append(mid)
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return added, latest


# ---------------------------------------------------------------------------
# label actions (all idempotent thanks to Gmail's modify semantics)
# ---------------------------------------------------------------------------
def modify_labels(service, message_id: str, add=None, remove=None) -> dict:
    body = {"addLabelIds": add or [], "removeLabelIds": remove or []}
    return client.execute(
        service.users().messages().modify(userId="me", id=message_id, body=body)
    )


def quarantine(service, message_id: str, conn) -> dict:
    """High-risk: hide from inbox under the Quarantine label. Never deleted."""
    return modify_labels(
        service, message_id, add=[conn.quarantine_label_id], remove=[INBOX_LABEL_ID]
    )


def release(service, message_id: str, conn) -> dict:
    """Return a message to the inbox and drop the quarantine/review labels."""
    remove = [
        lid for lid in (conn.quarantine_label_id, conn.needs_review_label_id) if lid
    ]
    return modify_labels(service, message_id, add=[INBOX_LABEL_ID], remove=remove)


def mark_needs_review(service, message_id: str, conn) -> dict:
    """Medium-risk: label but leave in the inbox (no INBOX removal)."""
    return modify_labels(service, message_id, add=[conn.needs_review_label_id])


def mark_processed(service, message_id: str, conn) -> dict:
    if not conn.processed_label_id:
        return {}
    return modify_labels(service, message_id, add=[conn.processed_label_id])


def mark_scan_failed(service, message_id: str, conn) -> dict:
    if not conn.scan_failed_label_id:
        return {}
    return modify_labels(service, message_id, add=[conn.scan_failed_label_id])


# ---------------------------------------------------------------------------
# minimal content extraction (Checkpoint 2 -- superseded by parser.py in CP3)
# ---------------------------------------------------------------------------
def _header(headers: list, name: str) -> str:
    name_l = name.lower()
    for h in headers or []:
        if h.get("name", "").lower() == name_l:
            return h.get("value", "")
    return ""


def _b64url(data: str) -> str:
    if not data:
        return ""
    try:
        return base64.urlsafe_b64decode(data.encode("utf-8")).decode(
            "utf-8", errors="replace"
        )
    except Exception:
        return ""


def _walk_for_body(payload: dict) -> str:
    """Depth-first search for a text/plain part, falling back to text/html.
    Deliberately simple -- CP3's parser.py handles nested multiparts,
    charsets, and attachments properly."""
    mime = payload.get("mimeType", "")
    body_data = payload.get("body", {}).get("data")
    if mime == "text/plain" and body_data:
        return _b64url(body_data)

    html_fallback = ""
    for part in payload.get("parts", []) or []:
        text = _walk_for_body(part)
        if text and part.get("mimeType") == "text/plain":
            return text
        if text and not html_fallback:
            html_fallback = text
    if mime == "text/html" and body_data:
        return _b64url(body_data)
    return html_fallback


def extract_basic(message: dict) -> dict:
    """Pull sender/subject/body/message-id/thread/history from a full Gmail
    message. Enough to feed the existing classifier during CP2."""
    payload = message.get("payload", {})
    headers = payload.get("headers", [])
    return {
        "gmail_message_id": message.get("id"),
        "gmail_thread_id": message.get("threadId"),
        "gmail_history_id": message.get("historyId"),
        "rfc_message_id": _header(headers, "Message-ID"),
        "sender": _header(headers, "From"),
        "subject": _header(headers, "Subject"),
        "date": _header(headers, "Date"),
        "body": _walk_for_body(payload).strip(),
    }
