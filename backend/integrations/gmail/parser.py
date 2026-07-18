"""
Full MIME email parser.

Parses raw RFC822 bytes into a structured ParsedEmail: headers (From,
Reply-To, Return-Path, To/Cc, Subject, Date, Message-ID, Received,
Authentication-Results/Received-SPF), decoded plain-text and HTML bodies,
extracted URLs (plain-text + HTML anchors with their visible text), and
attachment metadata + SHA-256 hashes.

Raw-bytes input on purpose: this one parser serves both connected Gmail
(fetched with format='raw') and uploaded .eml files (Checkpoint 4), so
there's a single, well-tested parsing path rather than two.

Safety: attachments are never executed and HTML is never rendered here --
only metadata, hashes, and text are extracted. No network requests are made
(no URL is fetched), so there's no SSRF surface.
"""

import re
import html
import hashlib
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from html.parser import HTMLParser
from urllib.parse import urlparse

from ml.features import extract_urls

MAX_BODY_CHARS = 200_000  # guard against pathologically huge bodies


@dataclass
class Attachment:
    filename: str
    content_type: str
    extension: str
    size: int
    sha256: str


@dataclass
class Link:
    href: str
    text: str  # visible anchor text (HTML) or "" for plain-text URLs
    source: str  # 'html' | 'text'


@dataclass
class ParsedEmail:
    from_display: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list = field(default_factory=list)
    cc: list = field(default_factory=list)
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received: list = field(default_factory=list)
    authentication_results: str = ""
    received_spf: str = ""
    text_body: str = ""
    html_body: str = ""
    links: list = field(default_factory=list)  # list[Link]
    attachments: list = field(default_factory=list)  # list[Attachment]
    parse_errors: list = field(default_factory=list)

    def body_for_classifier(self) -> str:
        """Best available text for the ML classifier: plain text if present,
        otherwise HTML with tags stripped."""
        if self.text_body:
            return self.text_body
        if self.html_body:
            return strip_html(self.html_body)
        return ""


class _AnchorExtractor(HTMLParser):
    """Collect (href, visible_text) pairs from <a> tags without rendering."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._href = None
        self._text_parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text_parts = []

    def handle_data(self, data):
        if self._href is not None:
            self._text_parts.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text_parts).strip()))
            self._href = None
            self._text_parts = []


def strip_html(html_text: str) -> str:
    """Remove tags and collapse whitespace -- for feeding HTML-only mail to
    the text classifier. Not a sanitiser; do not use for display."""
    no_scripts = re.sub(
        r"<(script|style)[^>]*>.*?</\1>", " ", html_text or "", flags=re.I | re.S
    )
    text = re.sub(r"<[^>]+>", " ", no_scripts)
    return html.unescape(re.sub(r"\s+", " ", text)).strip()


def _extension(filename: str) -> str:
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def _decode_part_text(part) -> str:
    try:
        content = part.get_content()
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="replace")
        return content or ""
    except Exception:
        # Fall back to raw decoded payload for malformed charsets.
        try:
            payload = part.get_payload(decode=True)
            return payload.decode("utf-8", errors="replace") if payload else ""
        except Exception:
            return ""


def parse(raw_bytes: bytes) -> ParsedEmail:
    """Parse raw RFC822 bytes into a ParsedEmail. Never raises on a merely
    malformed message -- parse issues are collected into parse_errors and the
    best-effort result is still returned."""
    result = ParsedEmail()
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as e:
        result.parse_errors.append(f"header_parse: {type(e).__name__}")
        # Last-ditch: try the compat32 parser which is more permissive.
        try:
            from email import message_from_bytes

            msg = message_from_bytes(raw_bytes)
        except Exception:
            return result

    # --- addresses / identity headers ---
    from_display, from_addr = parseaddr(str(msg.get("From", "")))
    result.from_display = from_display
    result.from_address = from_addr.lower()
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    result.reply_to = reply_addr.lower()
    _, rp_addr = parseaddr(str(msg.get("Return-Path", "")))
    result.return_path = rp_addr.lower()
    result.to = [a.lower() for _, a in getaddresses(msg.get_all("To", [])) if a]
    result.cc = [a.lower() for _, a in getaddresses(msg.get_all("Cc", [])) if a]

    result.subject = str(msg.get("Subject", "") or "")
    result.date = str(msg.get("Date", "") or "")
    result.message_id = str(msg.get("Message-ID", "") or "")
    result.received = [str(h) for h in msg.get_all("Received", [])]
    result.authentication_results = " ".join(
        str(h) for h in msg.get_all("Authentication-Results", [])
    )
    result.received_spf = " ".join(str(h) for h in msg.get_all("Received-SPF", []))

    # --- bodies + attachments ---
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        if disposition == "attachment" or (filename and disposition != "inline"):
            _record_attachment(part, filename, ctype, result)
            continue

        if ctype == "text/plain" and not result.text_body:
            result.text_body = _decode_part_text(part)[:MAX_BODY_CHARS]
        elif ctype == "text/html" and not result.html_body:
            result.html_body = _decode_part_text(part)[:MAX_BODY_CHARS]
        elif filename:
            # A named part that's neither of our body types -> treat as attach.
            _record_attachment(part, filename, ctype, result)

    _extract_links(result)
    return result


def _record_attachment(part, filename, ctype, result):
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:
        payload = b""
        result.parse_errors.append("attachment_decode")
    result.attachments.append(
        Attachment(
            filename=filename or "(unnamed)",
            content_type=ctype,
            extension=_extension(filename or ""),
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest() if payload else "",
        )
    )


def _extract_links(result: ParsedEmail):
    # Plain-text URLs.
    for url in extract_urls(result.text_body):
        result.links.append(Link(href=url, text="", source="text"))
    # HTML anchors (href + visible text).
    if result.html_body:
        try:
            extractor = _AnchorExtractor()
            extractor.feed(result.html_body)
            for href, text in extractor.links:
                if href and href.strip():
                    result.links.append(
                        Link(href=href.strip(), text=text, source="html")
                    )
        except Exception:
            result.parse_errors.append("html_link_parse")


# ---------------------------------------------------------------------------
# small URL helpers reused by analysis.py
# ---------------------------------------------------------------------------
def url_host(url: str):
    try:
        candidate = (
            url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", url) else "http://" + url
        )
        host = urlparse(candidate).hostname or ""
        return host.lower()
    except Exception:
        return ""


def url_scheme(url: str):
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):", url or "")
    return m.group(1).lower() if m else ""
