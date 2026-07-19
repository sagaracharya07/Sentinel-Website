"""
Gmail label management: discover or create Sentinel's labels once per
connection, and cache their ids on the GmailConnection so message actions
(quarantine/release) reference ids, not names.

Sentinel's labels (nested under a single "Sentinel" parent so they group
tidily in the Gmail sidebar):
    Sentinel/Processed      -- optional marker on classified-legitimate mail
    Sentinel/Needs Review   -- medium-risk, left in inbox for an analyst
    Sentinel/Quarantine     -- high-risk, INBOX removed (never deleted)
    Sentinel/Scan Failed    -- processing error, left in inbox

Duplicate-label prevention: labels are matched by name before creating, and
a create that races another (409) falls back to re-reading the list, so we
never create two labels with the same name.
"""

import time
import logging

from . import client
from .exceptions import GmailError

logger = logging.getLogger(__name__)

PARENT_LABEL = "Sentinel"
PROCESSED_LABEL = "Sentinel/Processed"
NEEDS_REVIEW_LABEL = "Sentinel/Needs Review"
QUARANTINE_LABEL = "Sentinel/Quarantine"
SCAN_FAILED_LABEL = "Sentinel/Scan Failed"

# Order matters: create the parent first so the children nest under it.
_REQUIRED_LABELS = [
    PARENT_LABEL,
    PROCESSED_LABEL,
    NEEDS_REVIEW_LABEL,
    QUARANTINE_LABEL,
    SCAN_FAILED_LABEL,
]


def list_labels(service) -> list[dict]:
    """All labels in the mailbox as [{id, name, ...}]."""
    resp = client.execute(service.users().labels().list(userId="me"))
    return resp.get("labels", [])


def _name_to_id(service) -> dict:
    return {lbl["name"]: lbl["id"] for lbl in list_labels(service)}


def find_label_id(service, name: str):
    return _name_to_id(service).get(name)


def create_label(service, name: str) -> str:
    """Create one label, returning its id.

    On ANY create conflict (permanent or retryable), always check whether
    the label already exists before deciding what to do next -- Gmail does
    not consistently report "alreadyExists" as the reason for a genuine
    duplicate; it can also come back as 409 "aborted" (seen in practice: a
    label created on an earlier attempt, then a later attempt tries to
    create it again and gets "aborted", not "alreadyExists"). Trusting the
    reason string to decide "is this actually a duplicate" was the original
    bug here -- a real duplicate reported as "aborted" would be retried
    forever, since nothing about blindly retrying the same create ever
    resolves a name that's already taken. Re-reading first sidesteps that:
    if it's really there, reuse it immediately; only retry when a fresh
    re-read confirms the label genuinely doesn't exist yet.
    """
    body = {
        "name": name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
    }
    attempts = 0
    max_attempts = 3
    while True:
        attempts += 1
        try:
            created = client.execute(
                service.users().labels().create(userId="me", body=body)
            )
            return created["id"]
        except (client.GmailPermanentError, client.GmailRetryableError) as e:
            existing = find_label_id(service, name)
            if existing:
                return existing
            if isinstance(e, client.GmailRetryableError) and attempts < max_attempts:
                # Genuinely not created yet (re-read confirmed it) and the
                # error is transient -- worth another attempt with backoff.
                time.sleep(min(0.5 * (2 ** (attempts - 1)), 3.0))
                continue
            raise


def ensure_sentinel_labels(service, conn) -> dict:
    """Ensure all Sentinel labels exist, caching their ids on the connection.
    Safe to call repeatedly -- existing labels are reused, never duplicated.
    Returns {name: id} for the four action labels.

    Each label is attempted independently, and whatever succeeds is saved to
    the connection immediately -- one label that keeps failing must not
    throw away progress on the other four. Without this, a single
    persistently-conflicting label meant every retry re-fought all five
    labels from scratch instead of just the one still missing, since the
    old version only wrote conn.*_label_id after the whole loop finished
    without raising. Now each retry only needs to resolve whatever's left.
    """
    from extensions import db

    existing = _name_to_id(service)
    ids = {}
    last_error = None
    for name in _REQUIRED_LABELS:
        try:
            ids[name] = existing.get(name) or create_label(service, name)
        except GmailError as e:
            last_error = e

    if PROCESSED_LABEL in ids:
        conn.processed_label_id = ids[PROCESSED_LABEL]
    if NEEDS_REVIEW_LABEL in ids:
        conn.needs_review_label_id = ids[NEEDS_REVIEW_LABEL]
    if QUARANTINE_LABEL in ids:
        conn.quarantine_label_id = ids[QUARANTINE_LABEL]
    if SCAN_FAILED_LABEL in ids:
        conn.scan_failed_label_id = ids[SCAN_FAILED_LABEL]
    db.session.commit()

    if last_error is not None:
        raise last_error

    return {
        "processed": conn.processed_label_id,
        "needs_review": conn.needs_review_label_id,
        "quarantine": conn.quarantine_label_id,
        "scan_failed": conn.scan_failed_label_id,
    }
