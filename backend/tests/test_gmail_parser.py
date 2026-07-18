"""Full MIME parser tests: headers, bodies, encodings, links, attachments."""

import hashlib
from email.message import EmailMessage

from integrations.gmail import parser


def _bytes(msg: EmailMessage) -> bytes:
    return msg.as_bytes()


def test_parse_plain_text_headers_and_body():
    m = EmailMessage()
    m["From"] = "Alice Example <alice@corp.example>"
    m["Subject"] = "Quarterly report"
    m.set_content("Here is the report http://links.example/report")
    p = parser.parse(_bytes(m))
    assert p.from_display == "Alice Example"
    assert p.from_address == "alice@corp.example"
    assert p.subject == "Quarterly report"
    assert "report" in p.text_body
    assert any(
        link.source == "text" and "links.example" in link.href for link in p.links
    )


def test_parse_html_only_body_stripped_for_classifier():
    m = EmailMessage()
    m["From"] = "b@corp.example"
    m.set_content("<p>Hello <b>world</b></p>", subtype="html")
    p = parser.parse(_bytes(m))
    assert p.text_body == ""
    assert "Hello" in p.html_body
    assert "Hello world" in p.body_for_classifier()


def test_parse_multipart_alternative_both_bodies():
    m = EmailMessage()
    m["From"] = "c@corp.example"
    m.set_content("plain version")
    m.add_alternative("<p>html version</p>", subtype="html")
    p = parser.parse(_bytes(m))
    assert "plain version" in p.text_body
    assert "html version" in p.html_body


def test_parse_encoded_subject_is_decoded():
    m = EmailMessage()
    m["From"] = "d@corp.example"
    m["Subject"] = "Ré: pàyment vérification"
    m.set_content("body")
    p = parser.parse(_bytes(m))
    assert p.subject == "Ré: pàyment vérification"


def test_parse_alternate_charset_body():
    m = EmailMessage()
    m["From"] = "e@corp.example"
    m.set_content("café münchen", charset="iso-8859-1")
    p = parser.parse(_bytes(m))
    assert "café" in p.text_body


def test_parse_missing_sender_is_empty():
    m = EmailMessage()
    m["Subject"] = "no from header"
    m.set_content("body")
    p = parser.parse(_bytes(m))
    assert p.from_address == ""


def test_parse_reply_to_and_return_path():
    m = EmailMessage()
    m["From"] = "svc@bank.example"
    m["Reply-To"] = "attacker@evil.example"
    m["Return-Path"] = "<bounce@evil.example>"
    m.set_content("body")
    p = parser.parse(_bytes(m))
    assert p.reply_to == "attacker@evil.example"
    assert p.return_path == "bounce@evil.example"


def test_parse_html_anchor_href_and_text():
    m = EmailMessage()
    m["From"] = "f@corp.example"
    m.set_content("plain")
    m.add_alternative(
        '<a href="http://evil.example/login">www.paypal.com</a>', subtype="html"
    )
    p = parser.parse(_bytes(m))
    html_links = [link for link in p.links if link.source == "html"]
    assert len(html_links) == 1
    assert html_links[0].href == "http://evil.example/login"
    assert html_links[0].text == "www.paypal.com"


def test_parse_attachment_metadata_and_hash():
    payload = b"PK\x03\x04 pretend zip bytes"
    m = EmailMessage()
    m["From"] = "g@corp.example"
    m.set_content("see attached")
    m.add_attachment(
        payload, maintype="application", subtype="zip", filename="invoice.zip"
    )
    p = parser.parse(_bytes(m))
    assert len(p.attachments) == 1
    att = p.attachments[0]
    assert att.filename == "invoice.zip"
    assert att.extension == "zip"
    assert att.size == len(payload)
    assert att.sha256 == hashlib.sha256(payload).hexdigest()


def test_parse_double_extension_attachment_filename_preserved():
    m = EmailMessage()
    m["From"] = "h@corp.example"
    m.set_content("body")
    m.add_attachment(
        b"MZ malware",
        maintype="application",
        subtype="octet-stream",
        filename="invoice.pdf.exe",
    )
    p = parser.parse(_bytes(m))
    assert p.attachments[0].filename == "invoice.pdf.exe"
    assert p.attachments[0].extension == "exe"


def test_parse_malformed_bytes_does_not_raise():
    p = parser.parse(b"\xff\xfe this is not a valid mime message at all")
    assert isinstance(p, parser.ParsedEmail)  # best-effort, no exception


def test_parse_nested_multipart_mixed_with_attachment():
    m = EmailMessage()
    m["From"] = "i@corp.example"
    m.set_content("outer plain")
    m.add_alternative("<p>outer html</p>", subtype="html")
    m.add_attachment(b"data", maintype="application", subtype="pdf", filename="doc.pdf")
    p = parser.parse(_bytes(m))
    assert "outer plain" in p.text_body
    assert "outer html" in p.html_body
    assert any(a.filename == "doc.pdf" for a in p.attachments)


def test_strip_html_removes_scripts():
    dirty = "<div>keep<script>alert(1)</script> me</div>"
    assert "alert" not in parser.strip_html(dirty)
    assert "keep" in parser.strip_html(dirty)
