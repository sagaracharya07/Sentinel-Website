"""
Email-security analysis: turn a ParsedEmail into structured, explainable
findings, layered *on top of* the ML classifier (it never alters the model's
probability -- see Phase 7). Four families:

  authentication -- SPF / DKIM / DMARC results, parsed from the provider's
                    Authentication-Results / Received-SPF headers. We parse
                    trusted provider-generated headers only; we do NOT perform
                    independent DNS validation, and don't claim to.
  sender         -- Reply-To / Return-Path / display-name mismatches, punycode
                    and raw-IP sender domains.
  link           -- displayed-domain vs actual-destination mismatch, link
                    shorteners, raw-IP destinations, dangerous schemes.
  attachment     -- executable / script / macro / archive / double-extension
                    filenames (metadata only -- nothing is opened or executed).

Each finding: {category, indicator, severity, summary, evidence}. Evidence is
short and escaped for safe display; full raw headers are never emitted.
"""

import re
import html
from dataclasses import dataclass

from ml.features import SHORTENER_DOMAINS, TRUSTED_BRANDS
from .parser import url_host, url_scheme

_AUTH_RESULTS = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "unknown",
}

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}

_EXECUTABLE_EXT = {"exe", "scr", "com", "bat", "cmd", "msi", "pif", "cpl", "jar", "app"}
_SCRIPT_EXT = {"js", "vbs", "vbe", "ps1", "wsf", "hta", "jse", "sh"}
_MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm"}
_ARCHIVE_EXT = {"zip", "rar", "7z", "iso", "img", "gz", "tar", "cab"}
_DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "png", "jpg", "jpeg", "gif"}


@dataclass
class Finding:
    category: str
    indicator: str
    severity: str
    summary: str
    evidence: str = ""

    def to_dict(self):
        return {
            "category": self.category,
            "indicator": self.indicator,
            "severity": self.severity,
            "summary": self.summary,
            "evidence": _safe(self.evidence),
        }


def _safe(text: str, limit: int = 200) -> str:
    text = (text or "")[:limit]
    return html.escape(text)


def _base_domain(host: str) -> str:
    """Approximate registrable domain: last two labels. Good enough to compare
    'mail.paypal.com' with 'paypal.com'; does not special-case multi-part TLDs
    like co.uk (documented approximation for this prototype)."""
    if not host:
        return ""
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _is_raw_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""))


# ---------------------------------------------------------------------------
# authentication
# ---------------------------------------------------------------------------
def parse_authentication(auth_results: str, received_spf: str = "") -> dict:
    """Extract spf/dkim/dmarc verdicts from provider headers. Returns each as
    one of the known result strings, or None if not present."""
    text = f"{auth_results} {received_spf}".lower()
    out = {"spf": None, "dkim": None, "dmarc": None}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}\s*=\s*([a-z]+)", text)
        if m and m.group(1) in _AUTH_RESULTS:
            out[mech] = m.group(1)
    # Received-SPF: often "pass (google.com: ...)" with the result leading.
    if out["spf"] is None and received_spf:
        m = re.match(r"\s*([a-z]+)", received_spf.strip().lower())
        if m and m.group(1) in _AUTH_RESULTS:
            out["spf"] = m.group(1)
    return out


def _auth_findings(parsed) -> list:
    results = parse_authentication(parsed.authentication_results, parsed.received_spf)
    findings = []
    bad = {"fail": "high", "softfail": "medium", "permerror": "low", "temperror": "low"}

    for mech in ("spf", "dkim", "dmarc"):
        r = results[mech]
        if r in bad:
            findings.append(
                Finding(
                    "authentication",
                    f"{mech}_{r}",
                    bad[r],
                    f"{mech.upper()} check returned {r}",
                    f"Authentication-Results reported {mech}={r}",
                )
            )
        elif r == "none":
            sev = "medium" if mech == "dmarc" else "low"
            findings.append(
                Finding(
                    "authentication",
                    f"{mech}_none",
                    sev,
                    f"No {mech.upper()} result",
                    f"{mech}=none in authentication headers",
                )
            )
    if all(v is None for v in results.values()):
        findings.append(
            Finding(
                "authentication",
                "auth_absent",
                "low",
                "No authentication results present",
                "Message carried no Authentication-Results/Received-SPF headers",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# sender identity
# ---------------------------------------------------------------------------
def _sender_findings(parsed) -> list:
    findings = []
    from_addr = parsed.from_address
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    from_base = _base_domain(from_domain)

    if parsed.reply_to and "@" in parsed.reply_to:
        rt_base = _base_domain(parsed.reply_to.split("@")[-1])
        if from_base and rt_base and rt_base != from_base:
            findings.append(
                Finding(
                    "sender",
                    "reply_to_mismatch",
                    "medium",
                    "Reply-To domain differs from From",
                    f"From {from_domain}, Reply-To {parsed.reply_to.split('@')[-1]}",
                )
            )

    if parsed.return_path and "@" in parsed.return_path:
        rp_base = _base_domain(parsed.return_path.split("@")[-1])
        if from_base and rp_base and rp_base != from_base:
            findings.append(
                Finding(
                    "sender",
                    "return_path_mismatch",
                    "low",
                    "Return-Path domain differs from From",
                    f"From {from_domain}, Return-Path {parsed.return_path.split('@')[-1]}",
                )
            )

    if from_domain and _is_raw_ip(from_domain):
        findings.append(
            Finding(
                "sender",
                "sender_raw_ip",
                "high",
                "Sender uses a raw IP domain",
                from_domain,
            )
        )
    if from_domain.startswith("xn--") or ".xn--" in from_domain:
        findings.append(
            Finding(
                "sender",
                "punycode_domain",
                "medium",
                "Sender domain uses punycode (possible lookalike)",
                from_domain,
            )
        )

    # Display name references a trusted brand the sending domain doesn't match.
    display_l = (parsed.from_display or "").lower()
    for brand in TRUSTED_BRANDS:
        if (
            brand in display_l
            and from_domain
            and brand.replace(" ", "") not in from_domain
        ):
            findings.append(
                Finding(
                    "sender",
                    "display_name_brand_mismatch",
                    "high",
                    f'Display name references "{brand}" but domain is {from_domain}',
                    f'"{parsed.from_display}" <{from_addr}>',
                )
            )
            break
    return findings


# ---------------------------------------------------------------------------
# links
# ---------------------------------------------------------------------------
def _link_findings(parsed) -> list:
    findings = []
    seen_indicators = set()

    def add(indicator, severity, summary, evidence):
        key = (indicator, evidence)
        if key not in seen_indicators:
            seen_indicators.add(key)
            findings.append(Finding("link", indicator, severity, summary, evidence))

    for link in parsed.links:
        href = link.href
        scheme = url_scheme(href)
        if scheme in ("javascript", "data", "vbscript"):
            add("dangerous_scheme", "high", f"Link uses {scheme}: scheme", href)
            continue

        dest_host = url_host(href)
        if not dest_host:
            continue
        if _is_raw_ip(dest_host):
            add("link_raw_ip", "medium", "Link points to a raw IP address", dest_host)
        if (
            _base_domain(dest_host) in SHORTENER_DOMAINS
            or dest_host in SHORTENER_DOMAINS
        ):
            add("link_shortener", "medium", "Link uses a URL shortener", dest_host)
        if href.count("%") >= 6:
            add(
                "link_excessive_encoding",
                "low",
                "Link is heavily percent-encoded",
                href,
            )

        # Displayed-domain vs actual-destination (HTML anchors).
        if link.source == "html" and link.text:
            text_host = url_host(link.text.strip())
            if text_host and _base_domain(text_host) != _base_domain(dest_host):
                add(
                    "link_display_mismatch",
                    "high",
                    "Displayed link domain differs from its destination",
                    f"shows {text_host}, goes to {dest_host}",
                )
    return findings


# ---------------------------------------------------------------------------
# attachments
# ---------------------------------------------------------------------------
def _attachment_findings(parsed) -> list:
    findings = []
    for att in parsed.attachments:
        name = att.filename
        ext = att.extension
        # Double extension: e.g. invoice.pdf.exe
        parts = name.lower().rsplit(".", 2)
        if (
            len(parts) == 3
            and parts[1] in _DOC_EXT
            and parts[2] in (_EXECUTABLE_EXT | _SCRIPT_EXT)
        ):
            findings.append(
                Finding(
                    "attachment",
                    "double_extension",
                    "high",
                    "Attachment uses a deceptive double extension",
                    name,
                )
            )
        if ext in _EXECUTABLE_EXT:
            findings.append(
                Finding(
                    "attachment",
                    "executable_attachment",
                    "high",
                    "Executable attachment",
                    name,
                )
            )
        elif ext in _SCRIPT_EXT:
            findings.append(
                Finding(
                    "attachment", "script_attachment", "high", "Script attachment", name
                )
            )
        elif ext in _MACRO_EXT:
            findings.append(
                Finding(
                    "attachment",
                    "macro_office_attachment",
                    "medium",
                    "Macro-enabled Office attachment",
                    name,
                )
            )
        elif ext in _ARCHIVE_EXT:
            findings.append(
                Finding(
                    "attachment",
                    "archive_attachment",
                    "low",
                    "Archive attachment",
                    name,
                )
            )
    return findings


def analyze(parsed) -> list:
    """Run every analyzer and return all findings, most-severe first."""
    findings = (
        _auth_findings(parsed)
        + _sender_findings(parsed)
        + _link_findings(parsed)
        + _attachment_findings(parsed)
    )
    findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
    return findings


def analyze_to_dicts(parsed) -> list:
    return [f.to_dict() for f in analyze(parsed)]
