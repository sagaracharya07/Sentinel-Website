"""Email-security analysis tests: auth, sender, link, attachment findings."""

from integrations.gmail import analysis
from integrations.gmail.parser import ParsedEmail, Link, Attachment


def _indicators(findings):
    return {f.indicator for f in findings}


# --- authentication parsing --------------------------------------------------
def test_parse_authentication_all_present():
    hdr = "mx.google.com; spf=pass smtp.mailfrom=a.com; dkim=fail header.i=@a.com; dmarc=fail"
    out = analysis.parse_authentication(hdr)
    assert out == {"spf": "pass", "dkim": "fail", "dmarc": "fail"}


def test_parse_authentication_received_spf_fallback():
    out = analysis.parse_authentication("", "softfail (google.com: domain of x)")
    assert out["spf"] == "softfail"


def test_spf_fail_is_high_finding():
    p = ParsedEmail(authentication_results="mx; spf=fail; dkim=pass; dmarc=pass")
    findings = analysis._auth_findings(p)
    fails = [f for f in findings if f.indicator == "spf_fail"]
    assert fails and fails[0].severity == "high"


def test_dmarc_none_is_medium_finding():
    p = ParsedEmail(authentication_results="mx; spf=pass; dkim=pass; dmarc=none")
    assert "dmarc_none" in _indicators(analysis._auth_findings(p))


def test_absent_authentication_flagged():
    p = ParsedEmail(authentication_results="", received_spf="")
    assert "auth_absent" in _indicators(analysis._auth_findings(p))


# --- sender identity ---------------------------------------------------------
def test_reply_to_mismatch():
    p = ParsedEmail(from_address="svc@bank.example", reply_to="attacker@evil.example")
    assert "reply_to_mismatch" in _indicators(analysis._sender_findings(p))


def test_reply_to_same_base_domain_not_flagged():
    p = ParsedEmail(
        from_address="svc@bank.example", reply_to="noreply@mail.bank.example"
    )
    assert "reply_to_mismatch" not in _indicators(analysis._sender_findings(p))


def test_return_path_mismatch():
    p = ParsedEmail(from_address="svc@bank.example", return_path="bounce@evil.example")
    assert "return_path_mismatch" in _indicators(analysis._sender_findings(p))


def test_display_name_brand_mismatch():
    p = ParsedEmail(from_display="PayPal Support", from_address="x@evil.example")
    assert "display_name_brand_mismatch" in _indicators(analysis._sender_findings(p))


def test_punycode_sender_domain():
    p = ParsedEmail(from_address="user@xn--pypal-4ve.example")
    assert "punycode_domain" in _indicators(analysis._sender_findings(p))


def test_raw_ip_sender():
    p = ParsedEmail(from_address="user@192.168.10.5")
    assert "sender_raw_ip" in _indicators(analysis._sender_findings(p))


# --- links -------------------------------------------------------------------
def test_link_display_mismatch():
    p = ParsedEmail(
        links=[
            Link(href="http://evil.example/login", text="www.paypal.com", source="html")
        ]
    )
    assert "link_display_mismatch" in _indicators(analysis._link_findings(p))


def test_link_display_match_not_flagged():
    p = ParsedEmail(
        links=[
            Link(href="http://mail.paypal.com/login", text="paypal.com", source="html")
        ]
    )
    assert "link_display_mismatch" not in _indicators(analysis._link_findings(p))


def test_link_shortener():
    p = ParsedEmail(links=[Link(href="http://bit.ly/abc", text="", source="text")])
    assert "link_shortener" in _indicators(analysis._link_findings(p))


def test_link_raw_ip():
    p = ParsedEmail(links=[Link(href="http://203.0.113.9/pay", text="", source="text")])
    assert "link_raw_ip" in _indicators(analysis._link_findings(p))


def test_dangerous_scheme():
    p = ParsedEmail(
        links=[Link(href="javascript:alert(1)", text="click", source="html")]
    )
    assert "dangerous_scheme" in _indicators(analysis._link_findings(p))


# --- attachments -------------------------------------------------------------
def _att(filename):
    return Attachment(
        filename=filename,
        content_type="application/octet-stream",
        extension=filename.rsplit(".", 1)[-1].lower(),
        size=10,
        sha256="x",
    )


def test_executable_attachment():
    p = ParsedEmail(attachments=[_att("update.exe")])
    assert "executable_attachment" in _indicators(analysis._attachment_findings(p))


def test_script_attachment():
    p = ParsedEmail(attachments=[_att("payload.js")])
    assert "script_attachment" in _indicators(analysis._attachment_findings(p))


def test_macro_office_attachment():
    p = ParsedEmail(attachments=[_att("invoice.docm")])
    assert "macro_office_attachment" in _indicators(analysis._attachment_findings(p))


def test_double_extension_attachment():
    p = ParsedEmail(attachments=[_att("invoice.pdf.exe")])
    inds = _indicators(analysis._attachment_findings(p))
    assert "double_extension" in inds


def test_archive_attachment():
    p = ParsedEmail(attachments=[_att("bundle.zip")])
    assert "archive_attachment" in _indicators(analysis._attachment_findings(p))


# --- aggregate ---------------------------------------------------------------
def test_analyze_sorts_by_severity_and_serialises():
    p = ParsedEmail(
        from_address="x@evil.example",
        from_display="PayPal",
        authentication_results="mx; dmarc=none",
        attachments=[_att("readme.txt")],
    )
    dicts = analysis.analyze_to_dicts(p)
    assert dicts  # produced something
    severities = [analysis.SEVERITY_RANK[d["severity"]] for d in dicts]
    assert severities == sorted(severities, reverse=True)  # most-severe first
    # Evidence is HTML-escaped for safe display.
    for d in dicts:
        assert "<" not in d["evidence"]


def test_evidence_is_escaped():
    p = ParsedEmail(from_display="PayPal <script>", from_address="x@evil.example")
    for f in analysis.analyze(p):
        assert "<script>" not in f.to_dict()["evidence"]
