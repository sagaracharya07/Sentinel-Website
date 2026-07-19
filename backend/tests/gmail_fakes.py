"""
In-memory fake of the Gmail API service used across the Gmail tests.

It mimics the googleapiclient call chain
(service.users().messages().get(...).execute()) closely enough to exercise
labels.py / messages.py / sync.py for real -- including label creation,
message label modification (add/remove), history listing, and error
injection -- so tests never touch the network or need a real Google account.
"""

import json
import base64
from email.message import EmailMessage

import httplib2
from googleapiclient.errors import HttpError


def make_http_error(status: int, reason: str = "", message: str = "err") -> HttpError:
    resp = httplib2.Response({"status": status})
    resp.status = status
    body = {
        "error": {
            "code": status,
            "message": message,
            "errors": [{"reason": reason}] if reason else [],
        }
    }
    return HttpError(resp, json.dumps(body).encode("utf-8"))


def make_message(
    msg_id,
    sender="a@ext.example",
    subject="Hi",
    body="hello world",
    labels=None,
    thread_id=None,
    history_id="1",
    message_id_header=None,
    html=None,
):
    """A Gmail 'full' message dict with a text/plain (and optional text/html) part."""
    parts = []
    if body is not None:
        parts.append(
            {
                "mimeType": "text/plain",
                "body": {"data": base64.urlsafe_b64encode(body.encode()).decode()},
            }
        )
    if html is not None:
        parts.append(
            {
                "mimeType": "text/html",
                "body": {"data": base64.urlsafe_b64encode(html.encode()).decode()},
            }
        )
    headers = [
        {"name": "From", "value": sender},
        {"name": "Subject", "value": subject},
        {"name": "Message-ID", "value": message_id_header or f"<{msg_id}@ext.example>"},
        {"name": "Date", "value": "Mon, 1 Jan 2026 00:00:00 +0000"},
    ]
    return {
        "id": msg_id,
        "threadId": thread_id or f"t-{msg_id}",
        "historyId": history_id,
        "labelIds": list(labels if labels is not None else ["INBOX"]),
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": headers,
            "parts": parts,
        },
        # RFC822 'raw' form (base64url) consumed by the full parser via get_raw.
        "raw": build_raw(msg_id, sender, subject, body, html, message_id_header),
    }


def build_raw(
    msg_id,
    sender,
    subject,
    body,
    html=None,
    message_id_header=None,
    reply_to=None,
    return_path=None,
    auth_results=None,
    extra_headers=None,
):
    """Build a real RFC822 message and return it base64url-encoded (Gmail's
    'raw' format). Reused by parser/analysis tests to craft realistic input."""
    m = EmailMessage()
    m["From"] = sender
    m["Subject"] = subject if subject is not None else ""
    m["Message-ID"] = message_id_header or f"<{msg_id}@ext.example>"
    m["Date"] = "Mon, 1 Jan 2026 00:00:00 +0000"
    if reply_to:
        m["Reply-To"] = reply_to
    if return_path:
        m["Return-Path"] = return_path
    if auth_results:
        m["Authentication-Results"] = auth_results
    for k, v in (extra_headers or {}).items():
        m[k] = v
    if body is not None:
        m.set_content(body)
    if html is not None:
        if body is None:
            m.set_content("(html only)")
        m.add_alternative(html, subtype="html")
    return base64.urlsafe_b64encode(m.as_bytes()).decode()


class _Req:
    def __init__(self, fn):
        self._fn = fn

    def execute(self):
        return self._fn()


class _LabelsApi:
    def __init__(self, svc):
        self.s = svc

    def list(self, userId="me"):
        return _Req(lambda: {"labels": list(self.s.labels_store)})

    def create(self, userId="me", body=None):
        def do():
            self.s.create_count += 1
            name = body["name"]
            if self.s.abort_remaining > 0:
                self.s.abort_remaining -= 1
                raise make_http_error(409, "aborted", "concurrent modification")
            exists = any(x["name"] == name for x in self.s.labels_store)
            if exists or self.s.force_create_conflict:
                raise make_http_error(
                    409, self.s.create_conflict_reason, "Label name exists"
                )
            new = {"id": f"LBL-{self.s._next_label_id}", "name": name}
            self.s._next_label_id += 1
            self.s.labels_store.append(new)
            return new

        return _Req(do)


class _MessagesApi:
    def __init__(self, svc):
        self.s = svc

    def list(self, userId="me", maxResults=100, q=None, pageToken=None):
        def do():
            ids = [
                {"id": m["id"], "threadId": m["threadId"]}
                for m in self.s.messages_store.values()
            ]
            return {"messages": ids[:maxResults]}

        return _Req(do)

    def get(self, userId="me", id=None, format="full"):
        def do():
            if id not in self.s.messages_store:
                raise make_http_error(404, "notFound", "Message not found")
            if id in self.s.get_raises:
                raise self.s.get_raises[id]
            return self.s.messages_store[id]

        return _Req(do)

    def modify(self, userId="me", id=None, body=None):
        def do():
            self.s.modify_calls.append((id, body))
            msg = self.s.messages_store.get(id)
            if msg is None:
                raise make_http_error(404, "notFound", "Message not found")
            labels = set(msg.get("labelIds", []))
            labels.update(body.get("addLabelIds", []))
            labels.difference_update(body.get("removeLabelIds", []))
            msg["labelIds"] = list(labels)
            return msg

        return _Req(do)


class _HistoryApi:
    def __init__(self, svc):
        self.s = svc

    def list(
        self,
        userId="me",
        startHistoryId=None,
        historyTypes=None,
        maxResults=100,
        pageToken=None,
    ):
        def do():
            if self.s.history_expired:
                raise make_http_error(404, "notFound", "history id expired")
            return {
                "history": self.s.history_store,
                "historyId": self.s.profile["historyId"],
            }

        return _Req(do)


class FakeGmailService:
    def __init__(self, labels=None, messages=None, profile=None, history=None):
        self.labels_store = list(labels or [])
        self.messages_store = {m["id"]: m for m in (messages or [])}
        self.profile = profile or {
            "emailAddress": "ops@corp.example",
            "messagesTotal": 3,
            "historyId": "500",
        }
        self.history_store = list(history or [])
        self.history_expired = False
        self.force_create_conflict = False
        self.create_conflict_reason = "alreadyExists"  # Gmail doesn't always say this
        self.abort_remaining = 0  # next N label creates raise 409 "aborted"
        self.get_raises = {}  # message_id -> exception to raise on get()
        self.modify_calls = []
        self.create_count = 0
        self._next_label_id = 1000
        # watch/stop (push mode)
        self.watch_calls = []
        self.stop_calls = 0
        # epoch-ms expiration ~7 days out
        self.watch_expiration = "1900000000000"

    # chain roots
    def users(self):
        return self

    def labels(self):
        return _LabelsApi(self)

    def messages(self):
        return _MessagesApi(self)

    def history(self):
        return _HistoryApi(self)

    def getProfile(self, userId="me"):
        return _Req(lambda: dict(self.profile))

    def watch(self, userId="me", body=None):
        self.watch_calls.append(body)
        return _Req(
            lambda: {
                "historyId": self.profile["historyId"],
                "expiration": self.watch_expiration,
            }
        )

    def stop(self, userId="me"):
        self.stop_calls += 1
        return _Req(lambda: {})
