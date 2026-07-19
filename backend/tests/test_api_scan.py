"""
Integration tests for the scan -> persist -> history round trip, and the
feedback -> used_in_retrain flag flow that feeds Phase 2's retrain_task.
"""


def test_scan_requires_login(client):
    resp = client.post(
        "/api/scan", json={"subject": "x", "body": "y", "from": "a@b.com"}
    )
    assert resp.status_code == 401


def test_scan_requires_body(user_client):
    resp = user_client.post("/api/scan", json={"subject": "x", "from": "a@b.com"})
    assert resp.status_code == 400


def test_scan_rejects_oversized_body(user_client):
    resp = user_client.post(
        "/api/scan",
        json={
            "subject": "x",
            "from": "a@b.com",
            "body": "a" * 20001,
        },
    )
    assert resp.status_code == 400


def test_scan_persists_and_appears_in_history(user_client):
    resp = user_client.post(
        "/api/scan",
        json={
            "subject": "Your account will be suspended — verify now",
            "from": "PayPal Security <security@paypa1-support.com>",
            "body": "Dear Customer, verify your account immediately or it will be suspended. "
            "Click here: http://bit.ly/verify-acct",
        },
    )
    assert resp.status_code == 200
    scan = resp.get_json()
    assert scan["classification"] in ("Phishing", "Needs Review", "Legitimate")
    assert scan["scan_id"].startswith("SCN-")

    history = user_client.get("/api/history").get_json()
    assert any(s["scan_id"] == scan["scan_id"] for s in history)

    detail = user_client.get(f"/api/scan/{scan['scan_id']}").get_json()
    assert detail["scan_id"] == scan["scan_id"]


def test_scan_detail_forbidden_for_other_users(user_client, admin_client):
    scan = user_client.post(
        "/api/scan",
        json={
            "subject": "hi",
            "from": "a@b.com",
            "body": "just checking in",
        },
    ).get_json()

    from auth import create_user
    from app import app as flask_app

    with flask_app.app_context():
        create_user("other_user", "test_password_123", role="user")
    other_client = flask_app.test_client()
    other_client.post(
        "/api/auth/login",
        json={"username": "other_user", "password": "test_password_123"},
    )

    resp = other_client.get(f"/api/scan/{scan['scan_id']}")
    assert resp.status_code == 403

    # but an admin can see any scan
    resp = admin_client.get(f"/api/scan/{scan['scan_id']}")
    assert resp.status_code == 200


def test_feedback_flow_marks_scan_and_creates_unused_feedback_row(user_client):
    scan = user_client.post(
        "/api/scan",
        json={
            "subject": "hi",
            "from": "a@b.com",
            "body": "just checking in about lunch",
        },
    ).get_json()

    resp = user_client.post(
        "/api/feedback",
        json={
            "scan_id": scan["scan_id"],
            "corrected_label": "Phishing",
        },
    )
    assert resp.status_code == 200
    updated = resp.get_json()
    assert updated["user_feedback"] == "Phishing"
    # The correction must change the verdict itself, not just annotate it --
    # otherwise a queue that filters on classification (Needs Review, the
    # Detections verdict badge) never reflects it and the item is stuck
    # showing its original, now-superseded verdict forever.
    assert updated["classification"] == "Phishing"
    assert updated["risk_level"] == "High"

    from models import Feedback
    from app import app as flask_app

    with flask_app.app_context():
        fb = Feedback.query.filter_by(scan_id=scan["scan_id"]).first()
        assert fb is not None
        assert fb.corrected_label == "Phishing"
        assert fb.used_in_retrain is False
        # Feedback.original_label preserves the model's own original call
        # even though scan.classification has now moved on.
        assert fb.original_label == scan["classification"]


def test_feedback_rejects_invalid_label(user_client):
    scan = user_client.post(
        "/api/scan",
        json={
            "subject": "hi",
            "from": "a@b.com",
            "body": "just checking in",
        },
    ).get_json()
    resp = user_client.post(
        "/api/feedback",
        json={
            "scan_id": scan["scan_id"],
            "corrected_label": "Not A Real Label",
        },
    )
    assert resp.status_code == 400


def _login_other_user(flask_app, username="other_user"):
    from auth import create_user

    with flask_app.app_context():
        create_user(username, "test_password_123", role="user")
    other_client = flask_app.test_client()
    resp = other_client.post(
        "/api/auth/login", json={"username": username, "password": "test_password_123"}
    )
    assert resp.status_code == 200
    return other_client


def test_feedback_forbidden_for_other_users_scan(user_client, app):
    scan = user_client.post(
        "/api/scan",
        json={
            "subject": "hi",
            "from": "a@b.com",
            "body": "just checking in",
        },
    ).get_json()

    other_client = _login_other_user(app)
    resp = other_client.post(
        "/api/feedback",
        json={
            "scan_id": scan["scan_id"],
            "corrected_label": "Phishing",
        },
    )
    assert resp.status_code == 403


def test_feedback_allowed_for_admin_on_any_scan(user_client, admin_client):
    scan = user_client.post(
        "/api/scan",
        json={
            "subject": "hi",
            "from": "a@b.com",
            "body": "just checking in",
        },
    ).get_json()
    resp = admin_client.post(
        "/api/feedback",
        json={
            "scan_id": scan["scan_id"],
            "corrected_label": "Phishing",
        },
    )
    assert resp.status_code == 200


def test_history_hides_other_users_scans_by_default(user_client, app):
    user_client.post(
        "/api/scan",
        json={"subject": "mine", "from": "a@b.com", "body": "my own message here"},
    )

    other_client = _login_other_user(app)
    other_client.post(
        "/api/scan",
        json={"subject": "theirs", "from": "a@b.com", "body": "their own message here"},
    )

    history = other_client.get("/api/history").get_json()
    subjects = {s["subject"] for s in history}
    assert "theirs" in subjects
    assert "mine" not in subjects


def test_history_ignores_client_supplied_mine_param(user_client, app):
    """Ownership must be server-enforced, not opt-in via ?mine=true."""
    user_client.post(
        "/api/scan",
        json={"subject": "mine", "from": "a@b.com", "body": "my own message here"},
    )
    other_client = _login_other_user(app)
    other_client.post(
        "/api/scan",
        json={"subject": "theirs", "from": "a@b.com", "body": "their own message here"},
    )

    history = other_client.get("/api/history?mine=false").get_json()
    subjects = {s["subject"] for s in history}
    assert "mine" not in subjects


def test_history_shows_all_scans_for_admin(user_client, admin_client):
    user_client.post(
        "/api/scan",
        json={"subject": "mine", "from": "a@b.com", "body": "my own message here"},
    )
    history = admin_client.get("/api/history").get_json()
    assert any(s["subject"] == "mine" for s in history)


def test_history_filters_by_classification_needs_review(admin_client, app):
    _insert_scan(
        app,
        "SCN-NR1",
        "test_admin",
        confidence_score=0.6,
        prediction_confidence=0.6,
        classification="Needs Review",
    )
    _insert_scan(
        app,
        "SCN-PH1",
        "test_admin",
        confidence_score=0.9,
        prediction_confidence=0.9,
        classification="Phishing",
    )

    history = admin_client.get("/api/history?classification=Needs Review").get_json()
    assert {s["scan_id"] for s in history} == {"SCN-NR1"}


def test_history_filters_by_released(admin_client, app):
    from models import Scan
    from extensions import db

    with app.app_context():
        db.session.add(
            Scan(
                scan_id="SCN-REL1",
                sender="a@b.com",
                subject="released one",
                body="body",
                classification="Phishing",
                status="Delivered",
                created_by="test_admin",
                notes="Released by admin — marked false positive",
            )
        )
        db.session.add(
            Scan(
                scan_id="SCN-NOTREL1",
                sender="a@b.com",
                subject="never touched",
                body="body",
                classification="Legitimate",
                status="Delivered",
                created_by="test_admin",
            )
        )
        db.session.commit()

    history = admin_client.get("/api/history?released=true").get_json()
    subjects = {s["scan_id"] for s in history}
    assert "SCN-REL1" in subjects
    assert "SCN-NOTREL1" not in subjects


def test_history_filters_combine_with_ownership_scoping_for_regular_user(
    user_client, app
):
    """A non-admin applying a classification/released filter must still
    only ever see their own scans -- filters narrow within ownership
    scoping, they never widen access to it."""
    _insert_scan(
        app,
        "SCN-MINE-NR",
        "test_user",
        confidence_score=0.6,
        prediction_confidence=0.6,
        classification="Needs Review",
    )
    _insert_scan(
        app,
        "SCN-OTHER-NR",
        "someone_else",
        confidence_score=0.6,
        prediction_confidence=0.6,
        classification="Needs Review",
    )

    history = user_client.get("/api/history?classification=Needs Review").get_json()
    scan_ids = {s["scan_id"] for s in history}
    assert "SCN-MINE-NR" in scan_ids
    assert "SCN-OTHER-NR" not in scan_ids


def test_stats_scoped_to_own_scans_for_regular_user(user_client, app):
    user_client.post(
        "/api/scan",
        json={"subject": "mine", "from": "a@b.com", "body": "my own message here"},
    )
    other_client = _login_other_user(app)
    other_client.post(
        "/api/scan",
        json={"subject": "theirs", "from": "a@b.com", "body": "their own message here"},
    )

    stats = other_client.get("/api/stats").get_json()
    assert stats["total"] == 1
    assert stats["scope"] == "own_scans"


def test_stats_global_for_admin(user_client, admin_client):
    user_client.post(
        "/api/scan",
        json={"subject": "mine", "from": "a@b.com", "body": "my own message here"},
    )
    stats = admin_client.get("/api/stats").get_json()
    assert stats["total"] >= 1
    assert stats["scope"] == "all_users"


def _insert_scan(
    app,
    scan_id,
    created_by,
    confidence_score,
    prediction_confidence,
    classification="Legitimate",
    status="Delivered",
    source="manual",
):
    from models import Scan
    from extensions import db

    with app.app_context():
        db.session.add(
            Scan(
                scan_id=scan_id,
                sender="a@b.com",
                subject=scan_id,
                body="body",
                classification=classification,
                confidence_score=confidence_score,
                prediction_confidence=prediction_confidence,
                status=status,
                created_by=created_by,
                source=source,
            )
        )
        db.session.commit()


def test_stats_pending_review_counts_quarantined_and_flagged_only(admin_client, app):
    _insert_scan(
        app,
        "SCN-Q1",
        "test_admin",
        confidence_score=0.9,
        prediction_confidence=0.9,
        classification="Phishing",
        status="Quarantined",
        source="gmail",
    )
    _insert_scan(
        app,
        "SCN-F1",
        "test_admin",
        confidence_score=0.6,
        prediction_confidence=0.6,
        classification="Needs Review",
        status="Flagged",
        source="gmail",
    )
    _insert_scan(
        app,
        "SCN-D1",
        "test_admin",
        confidence_score=0.1,
        prediction_confidence=0.9,
        classification="Legitimate",
        status="Delivered",
    )

    stats = admin_client.get("/api/stats").get_json()
    assert stats["pending_review"] == 2


def test_stats_quarantined_excludes_quick_analysis_and_uploads(admin_client, app):
    # Quick Analysis ('manual') and .eml uploads ('upload') can carry
    # status='Quarantined'/'Flagged' purely from their classification label --
    # no real mailbox exists for either, so nothing was ever actually moved.
    # /api/stats must not count them as if a real mailbox action happened.
    _insert_scan(
        app,
        "SCN-REAL",
        "test_admin",
        confidence_score=0.9,
        prediction_confidence=0.9,
        classification="Phishing",
        status="Quarantined",
        source="gmail",
    )
    _insert_scan(
        app,
        "SCN-FAKE-MANUAL",
        "test_admin",
        confidence_score=0.9,
        prediction_confidence=0.9,
        classification="Phishing",
        status="Quarantined",
        source="manual",
    )
    _insert_scan(
        app,
        "SCN-FAKE-UPLOAD",
        "test_admin",
        confidence_score=0.9,
        prediction_confidence=0.9,
        classification="Phishing",
        status="Quarantined",
        source="upload",
    )

    stats = admin_client.get("/api/stats").get_json()
    assert stats["quarantined"] == 1


def test_avg_stats_distinguish_probability_from_confidence_for_legitimate_scan(
    admin_client, app
):
    """A highly legitimate scan (5% phishing probability) should report
    ~95% prediction confidence, not 5% -- conflating the two is exactly
    the bug being fixed."""
    _insert_scan(
        app,
        "SCN-LEGIT1",
        "test_admin",
        confidence_score=0.05,
        prediction_confidence=0.95,
    )
    stats = admin_client.get("/api/stats").get_json()
    assert round(stats["avg_phishing_probability"], 2) == 0.05
    assert round(stats["avg_prediction_confidence"], 2) == 0.95


def test_avg_stats_for_high_risk_phishing_scan(admin_client, app):
    _insert_scan(
        app,
        "SCN-PHISH1",
        "test_admin",
        confidence_score=0.91,
        prediction_confidence=0.91,
        classification="Phishing",
    )
    stats = admin_client.get("/api/stats").get_json()
    assert round(stats["avg_phishing_probability"], 2) == 0.91
    assert round(stats["avg_prediction_confidence"], 2) == 0.91


def test_avg_stats_for_mixed_scans(admin_client, app):
    _insert_scan(
        app, "SCN-MIX1", "test_admin", confidence_score=0.05, prediction_confidence=0.95
    )
    _insert_scan(
        app,
        "SCN-MIX2",
        "test_admin",
        confidence_score=0.91,
        prediction_confidence=0.91,
        classification="Phishing",
    )
    stats = admin_client.get("/api/stats").get_json()
    assert round(stats["avg_phishing_probability"], 3) == round((0.05 + 0.91) / 2, 3)
    assert round(stats["avg_prediction_confidence"], 3) == round((0.95 + 0.91) / 2, 3)


def test_avg_stats_falls_back_for_old_rows_with_null_prediction_confidence(
    admin_client, app
):
    """Old seeded/historical rows predate the prediction_confidence
    column -- stats must still compute a sensible confidence figure for
    them via the same max(p, 1-p) fallback as Scan.to_dict(), not treat
    them as 0 or exclude them silently."""
    _insert_scan(
        app, "SCN-OLD1", "test_admin", confidence_score=0.1, prediction_confidence=None
    )
    stats = admin_client.get("/api/stats").get_json()
    assert round(stats["avg_phishing_probability"], 2) == 0.10
    assert round(stats["avg_prediction_confidence"], 2) == 0.90


def test_avg_stats_present_and_role_scoped_for_regular_user(user_client, app):
    _insert_scan(
        app, "SCN-USR1", "test_user", confidence_score=0.2, prediction_confidence=0.8
    )
    other_client = _login_other_user(app)
    _insert_scan(
        app,
        "SCN-OTH1",
        "other_user",
        confidence_score=0.99,
        prediction_confidence=0.99,
        classification="Phishing",
    )

    stats = user_client.get("/api/stats").get_json()
    assert round(stats["avg_phishing_probability"], 2) == 0.20
    assert round(stats["avg_prediction_confidence"], 2) == 0.80
    assert "avg_confidence" not in stats

    other_stats = other_client.get("/api/stats").get_json()
    assert round(other_stats["avg_phishing_probability"], 2) == 0.99
