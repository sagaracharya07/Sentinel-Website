"""
Feature extraction for the Sentinel AI Phishing Detection Platform.

This module implements the NLP + engineered-feature pipeline described in
the project proposal, Section 2.2 (Server-End Functional Requirements,
FR-SE-05 / FR-SE-06) and Section 6.4-6.5 (pseudocode: ParseEmail,
ScanEmailWithAI). It is the single source of truth for feature extraction,
used identically by:
  - ml/train.py       (building the training matrix)
  - ml/retrain.py      (rebuilding the training matrix with feedback added)
  - ml/infer.py         (scoring a live email at request time)

Two feature families are produced and concatenated:
  1. TF-IDF vector over the normalised subject+body text (captures the
     general language patterns a Random Forest can split on).
  2. A small set of hand-engineered, explainable signals (urgency
     language, credential requests, suspicious URLs, sender/brand
     mismatch, formatting anomalies) that mirror what a human analyst
     looks for and let the platform surface *why* an email was flagged,
     satisfying the "explainable scoring" / FR-FE-05 requirement.
"""
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Phrase dictionaries (kept close to the original client-side classifier so
# the explanations users saw in the v1 demo remain meaningful)
# ---------------------------------------------------------------------------
URGENCY_PHRASES = [
    "act now", "verify your account", "account suspended", "confirm your identity",
    "urgent action required", "your account will be closed", "immediate action",
    "click here immediately", "limited time", "final notice", "unusual activity",
    "unauthorized login", "suspended your account", "expire in 24 hours",
    "action required", "security alert", "failure to comply", "payment failed",
    "reactivate your account", "confirm now", "verify now", "will be permanently",
]

CREDENTIAL_PHRASES = [
    "password", "login credentials", "social security", "credit card number",
    "bank account", "pin number", "verify your password", "update your billing",
    "ssn", "confirm your password", "card verification", "routing number",
    "account number", "wire transfer",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer", "dear account holder",
    "dear member", "dear beneficiary", "dear sir/madam", "dear friend",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at",
}

TRUSTED_BRANDS = [
    "paypal", "microsoft", "apple", "amazon", "netflix", "commonwealth bank",
    "anz", "westpac", "nab", "auspost", "ato", "google", "facebook", "instagram",
    "chase", "wells fargo", "irs", "docusign",
]


def _count_hits(text_lower, phrases):
    return [p for p in phrases if p in text_lower]


def extract_urls(text):
    return re.findall(r'\b((?:https?://|www\.)[^\s<>"\')]+)', text or "", flags=re.IGNORECASE)


def _domain(url):
    try:
        withproto = url if url.startswith("http") else "http://" + url
        host = urlparse(withproto).hostname or ""
        return host.lower().lstrip("www.")
    except Exception:
        return None


def _is_raw_ip(host):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host or ""))


def engineered_features(subject: str, body: str, sender: str = ""):
    """
    Returns (numeric_feature_vector: list[float], findings: list[dict])

    findings mirrors what the UI displays: a list of {type, detail, weight,
    severity} explaining which signals fired, so the platform stays
    explainable rather than a black box (Section 7.6 Design Justification).
    """
    subject = "" if subject is None or isinstance(subject, float) else str(subject)
    body = "" if body is None or isinstance(body, float) else str(body)
    sender = "" if sender is None or isinstance(sender, float) else str(sender)
    combined = f"{subject}\n{body}"
    text_lower = combined.lower()
    findings = []

    urgency_hits = _count_hits(text_lower, URGENCY_PHRASES)
    cred_hits = _count_hits(text_lower, CREDENTIAL_PHRASES)
    greet_hits = _count_hits(text_lower, GENERIC_GREETINGS)

    urls = extract_urls(combined)
    shortener_hits, raw_ip_hits, brand_mismatch_hits = [], [], []
    for u in urls:
        host = _domain(u)
        if not host:
            continue
        if host in SHORTENER_DOMAINS:
            shortener_hits.append(host)
        if _is_raw_ip(host):
            raw_ip_hits.append(host)
        for brand in TRUSTED_BRANDS:
            if brand in text_lower and brand.replace(" ", "") not in host:
                brand_mismatch_hits.append((host, brand))

    exclaims = combined.count("!")
    caps_words = len(re.findall(r"\b[A-Z]{4,}\b", combined))

    sender_mismatch = 0
    sender_lower = sender.lower()
    domain_match = re.search(r"@([\w.\-]+)", sender_lower)
    sender_domain = domain_match.group(1) if domain_match else None
    for brand in TRUSTED_BRANDS:
        if brand in sender_lower and sender_domain and brand.replace(" ", "") not in sender_domain:
            sender_mismatch += 1
            findings.append({
                "type": "Sender / brand mismatch",
                "detail": f'Display name references "{brand}" but sender domain is "{sender_domain}"',
                "weight": 18, "severity": "high",
            })

    word_count = len(combined.split())
    short_with_link = 1 if (0 < word_count < 40 and len(urls) > 0) else 0

    if urgency_hits:
        findings.append({
            "type": "Urgency / pressure language",
            "detail": ", ".join(f'"{p}"' for p in urgency_hits[:4]),
            "weight": min(len(urgency_hits) * 9, 30),
            "severity": "high" if len(urgency_hits) > 2 else "medium",
        })
    if cred_hits:
        findings.append({
            "type": "Requests sensitive information",
            "detail": ", ".join(f'"{p}"' for p in cred_hits[:4]),
            "weight": min(len(cred_hits) * 11, 26),
            "severity": "high",
        })
    if greet_hits:
        findings.append({
            "type": "Generic greeting",
            "detail": f'"{greet_hits[0]}" — not addressed by name',
            "weight": 8, "severity": "low",
        })
    if shortener_hits or raw_ip_hits or brand_mismatch_hits or len(urls) >= 3:
        notes = []
        w = 0
        if shortener_hits:
            notes.append(f"{shortener_hits[0]} (link shortener)"); w += 12
        if raw_ip_hits:
            notes.append(f"{raw_ip_hits[0]} (raw IP address link)"); w += 16
        if brand_mismatch_hits:
            host, brand = brand_mismatch_hits[0]
            notes.append(f'link domain "{host}" does not match mentioned brand "{brand}"'); w += 10
        if len(urls) >= 3:
            notes.append(f"{len(urls)} links in one message"); w += 6
        findings.append({
            "type": "Suspicious links", "detail": "; ".join(notes),
            "weight": min(w, 34), "severity": "high" if w > 18 else "medium",
        })
    if exclaims >= 3 or caps_words >= 2:
        findings.append({
            "type": "Formatting anomalies",
            "detail": f"{exclaims} exclamation marks, {caps_words} all-caps word(s)",
            "weight": min(exclaims * 2 + caps_words * 3, 14), "severity": "low",
        })
    if short_with_link:
        findings.append({
            "type": "Low-content message with link",
            "detail": f"Only {word_count} words but includes a link — typical of rushed phishing sends",
            "weight": 6, "severity": "low",
        })

    highlights = list(dict.fromkeys(
        urgency_hits + cred_hits + greet_hits + [u for u in urls]
    ))

    numeric = [
        len(urgency_hits), len(cred_hits), len(greet_hits),
        len(urls), len(shortener_hits), len(raw_ip_hits), len(brand_mismatch_hits),
        exclaims, caps_words, sender_mismatch, short_with_link, word_count,
        1 if word_count == 0 else 0,
    ]
    return numeric, findings, highlights


NUMERIC_FEATURE_NAMES = [
    "urgency_hits", "credential_hits", "generic_greeting_hits", "url_count",
    "shortener_count", "raw_ip_count", "brand_mismatch_count", "exclaim_count",
    "caps_word_count", "sender_mismatch", "short_with_link", "word_count", "empty_body",
]
