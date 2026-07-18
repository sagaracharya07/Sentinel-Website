"""
Unit tests for ml/features.py's engineered_features() -- the explainable
signal-extraction half of the classifier (the other half, TF-IDF, isn't
individually interpretable, so these signals are what the UI shows the
user as "why was this flagged"). Pure unit tests: no Flask app, no DB.
"""

from ml.features import engineered_features


def _finding_types(findings):
    return {f["type"] for f in findings}


def test_urgency_language_detected():
    numeric, findings, highlights = engineered_features(
        subject="Act now",
        body="Your account will be suspended. Act now to verify your account.",
        sender="security@example.com",
    )
    assert "Urgency / pressure language" in _finding_types(findings)
    assert any("act now" in h.lower() for h in highlights)


def test_credential_request_detected():
    numeric, findings, highlights = engineered_features(
        subject="Billing update",
        body="Please confirm your password and bank account number to continue.",
        sender="billing@example.com",
    )
    assert "Requests sensitive information" in _finding_types(findings)


def test_generic_greeting_detected():
    numeric, findings, highlights = engineered_features(
        subject="Notice",
        body="Dear Customer, please review the attached statement.",
        sender="notices@example.com",
    )
    assert "Generic greeting" in _finding_types(findings)


def test_no_generic_greeting_when_addressed_by_name():
    numeric, findings, highlights = engineered_features(
        subject="Notice",
        body="Hi Sagar, please review the attached statement.",
        sender="notices@example.com",
    )
    assert "Generic greeting" not in _finding_types(findings)


def test_link_shortener_detected():
    numeric, findings, highlights = engineered_features(
        subject="Verify",
        body="Click here to verify: http://bit.ly/verify-acct",
        sender="alerts@example.com",
    )
    assert "Suspicious links" in _finding_types(findings)


def test_raw_ip_url_detected():
    numeric, findings, highlights = engineered_features(
        subject="Login",
        body="Confirm your login at http://192.168.1.50/login",
        sender="alerts@example.com",
    )
    assert "Suspicious links" in _finding_types(findings)


def test_brand_sender_mismatch_detected():
    numeric, findings, highlights = engineered_features(
        subject="Account alert",
        body="Your PayPal account needs attention.",
        sender="PayPal Security <security@paypa1-support.com>",
    )
    assert "Sender / brand mismatch" in _finding_types(findings)


def test_no_brand_mismatch_for_legitimate_domain():
    numeric, findings, highlights = engineered_features(
        subject="Receipt",
        body="Your PayPal receipt is attached.",
        sender="service@paypal.com",
    )
    assert "Sender / brand mismatch" not in _finding_types(findings)


def test_formatting_anomalies_detected():
    numeric, findings, highlights = engineered_features(
        subject="WARNING",
        body="ACT NOW!!! YOUR ACCOUNT IS AT RISK!!! CONFIRM IMMEDIATELY!!!",
        sender="alerts@example.com",
    )
    assert "Formatting anomalies" in _finding_types(findings)


def test_short_message_with_link_detected():
    numeric, findings, highlights = engineered_features(
        subject="",
        body="Check this out http://example.com/x",
        sender="friend@example.com",
    )
    assert "Low-content message with link" in _finding_types(findings)


def test_benign_short_message_has_no_findings():
    numeric, findings, highlights = engineered_features(
        subject="Lunch tomorrow?",
        body="Hey, are we still on for lunch tomorrow at 12? Let me know.",
        sender="friend.colleague@gmail.com",
    )
    assert findings == []


def test_handles_none_and_missing_fields_gracefully():
    numeric, findings, highlights = engineered_features(
        subject=None, body=None, sender=None
    )
    assert isinstance(numeric, list)
    assert findings == []
