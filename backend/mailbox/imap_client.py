"""
Real IMAP mailbox integration for the Sentinel AI platform.

This is what makes the platform actually "connected to email" instead of
copy-paste: it logs into a real mailbox over IMAP, pulls new messages,
and can move high-risk messages into a real quarantine folder in that
same mailbox.

Configuration lives in environment variables (see backend/.env.example) --
never hardcode credentials, never commit a real .env file. This module
never emails anyone or deletes anything permanently; the only mailbox
mutation it performs is MOVE (to a quarantine folder you control), which
is reversible from the mail client itself at any time.

Requires an "app password" for providers with 2FA (Gmail, Outlook) rather
than your real account password -- this is standard practice and lets
you revoke the platform's mailbox access without changing your login
password. See README section "Connecting a real mailbox" for the
provider-specific setup steps.
"""

import os
from dataclasses import dataclass
from typing import Optional

from imap_tools import MailBox, AND, MailMessageFlags
from imap_tools.query import Header


@dataclass
class MailboxConfig:
    host: str
    port: int
    username: str
    password: str
    inbox_folder: str = "INBOX"
    quarantine_folder: str = "Sentinel-Quarantine"
    # No use_ssl field: this app connects over IMAP-over-SSL only (see
    # connect() below), full stop. A prior MAILBOX_USE_SSL env var was read
    # into config but never actually consulted by connect() -- setting it
    # to false silently did nothing, which is worse than not offering the
    # option at all for a phishing-security tool. Removed rather than
    # wired up, since plaintext IMAP has no legitimate use case here.

    @classmethod
    def from_env(cls) -> Optional["MailboxConfig"]:
        host = os.environ.get("MAILBOX_HOST")
        username = os.environ.get("MAILBOX_USERNAME")
        password = os.environ.get("MAILBOX_PASSWORD")
        if not (host and username and password):
            return None
        return cls(
            host=host,
            port=int(os.environ.get("MAILBOX_PORT", "993")),
            username=username,
            password=password,
            inbox_folder=os.environ.get("MAILBOX_INBOX_FOLDER", "INBOX"),
            quarantine_folder=os.environ.get(
                "MAILBOX_QUARANTINE_FOLDER", "Sentinel-Quarantine"
            ),
        )


class MailboxError(Exception):
    pass


def connect(cfg: MailboxConfig) -> MailBox:
    """Opens and logs into the mailbox over IMAP-over-SSL (imap_tools'
    MailBox is always the SSL-only client -- there is no plaintext
    fallback in this codebase). Caller is responsible for closing it (use
    as a context manager: `with connect(cfg) as mb:`)."""
    try:
        mb = MailBox(cfg.host, port=cfg.port).login(
            cfg.username, cfg.password, initial_folder=cfg.inbox_folder
        )
        return mb
    except Exception as e:
        raise MailboxError(f"Could not connect/login to {cfg.host}: {e}") from e


def test_connection(cfg: MailboxConfig) -> dict:
    """Used by the admin 'Test connection' button -- connects, reads
    folder status, disconnects. Never leaves a session open."""
    try:
        with connect(cfg) as mb:
            mb.folder.set(cfg.inbox_folder)
            status = mb.folder.status(cfg.inbox_folder)
            return {
                "ok": True,
                "message_count": status.get("MESSAGES", 0),
                "folder": cfg.inbox_folder,
            }
    except MailboxError as e:
        return {"ok": False, "error": str(e)}


def ensure_quarantine_folder(mb: MailBox, cfg: MailboxConfig):
    try:
        folders = [f.name for f in mb.folder.list()]
        if cfg.quarantine_folder not in folders:
            mb.folder.create(cfg.quarantine_folder)
    except Exception as e:
        raise MailboxError(
            f"Could not create/list quarantine folder {cfg.quarantine_folder!r}: {e}"
        ) from e


def fetch_new_messages(cfg: MailboxConfig, known_uids: set, limit: int = 25):
    """
    Connects, lists messages in the watched folder not already in
    `known_uids` (the set of UIDs Sentinel has already scanned, tracked
    in the Scan table -- see models.Scan.mailbox_uid), and returns plain
    dicts ready to feed into ml.infer.classify(). Does not mutate
    anything on the server -- fetching is read-only.

    Returns (messages, stats) rather than a bare list, so the caller
    (mailbox/sync.py) can report real per-batch counts (fetched vs.
    skipped-as-duplicate vs. failed-to-parse) instead of only a final
    "new_messages" total -- see Phase 5's summary-counts requirement.
    """
    results = []
    stats = {"fetched": 0, "skipped_duplicates": 0, "failed_parse": 0}
    try:
        with connect(cfg) as mb:
            mb.folder.set(cfg.inbox_folder)
            for msg in mb.fetch(
                AND(all=True), limit=limit, reverse=True, mark_seen=False
            ):
                stats["fetched"] += 1
                if msg.uid in known_uids:
                    stats["skipped_duplicates"] += 1
                    continue
                # A malformed message (bad headers, undecodable body) can
                # throw mid-iteration; skip just that message instead of
                # losing the whole fetch batch or crashing the sync. Log
                # only the UID -- never the message body/headers, which
                # could contain sensitive content.
                try:
                    results.append(
                        {
                            "uid": msg.uid,
                            "message_id": msg.headers.get("message-id", [""])[0]
                            if msg.headers.get("message-id")
                            else "",
                            "sender": msg.from_ or "",
                            "subject": msg.subject or "",
                            "body": (msg.text or msg.html or "").strip(),
                            "date": msg.date.isoformat() if msg.date else None,
                        }
                    )
                except Exception:
                    stats["failed_parse"] += 1
                    continue
                if len(results) >= limit:
                    break
    except MailboxError:
        raise
    except Exception as e:
        raise MailboxError(
            f"Failed to fetch messages from {cfg.inbox_folder}: {e}"
        ) from e
    return results, stats


def quarantine_message(cfg: MailboxConfig, uid: str):
    """Moves one message (by UID) from the watched folder into the
    quarantine folder. This is the real-world action behind UC-03
    ('Quarantine or Flag Email') -- reversible, auditable, never a delete."""
    try:
        with connect(cfg) as mb:
            mb.folder.set(cfg.inbox_folder)
            ensure_quarantine_folder(mb, cfg)
            mb.move([uid], cfg.quarantine_folder)
    except MailboxError:
        raise
    except Exception as e:
        raise MailboxError(
            f"Could not move message {uid} to {cfg.quarantine_folder}: {e}"
        ) from e


def flag_message(cfg: MailboxConfig, uid: str):
    """For 'Flagged' (medium-risk) mail: leave it in the inbox but mark
    it with the standard IMAP \\Flagged flag so it's visibly marked in
    any real mail client, without moving it."""
    try:
        with connect(cfg) as mb:
            mb.folder.set(cfg.inbox_folder)
            mb.flag([uid], [MailMessageFlags.FLAGGED], True)
    except MailboxError:
        raise
    except Exception as e:
        raise MailboxError(f"Could not flag message {uid}: {e}") from e


def unquarantine_message(cfg: MailboxConfig, message_id: str):
    """
    Moves a previously-quarantined message back to the inbox folder --
    this is what makes an admin's "Release (false positive)" action a
    real, reversible mailbox operation rather than only a database
    status flip. IMAP UIDs are only unique *within* a folder, so the
    original UID recorded at quarantine-time is no longer valid once the
    message has moved; RFC Message-ID is stable across folders/moves, so
    that's what's used to relocate it.
    """
    if not message_id:
        raise MailboxError(
            "No Message-ID recorded for this scan — cannot locate it in the quarantine folder"
        )
    try:
        with connect(cfg) as mb:
            mb.folder.set(cfg.quarantine_folder)
            matches = list(
                mb.fetch(
                    AND(header=Header("Message-ID", message_id)),
                    limit=1,
                    mark_seen=False,
                )
            )
            if not matches:
                raise MailboxError(
                    f"Message not found in {cfg.quarantine_folder} (already moved/deleted manually?)"
                )
            mb.move([matches[0].uid], cfg.inbox_folder)
    except MailboxError:
        raise
    except Exception as e:
        raise MailboxError(
            f"Could not release message back to {cfg.inbox_folder}: {e}"
        ) from e
