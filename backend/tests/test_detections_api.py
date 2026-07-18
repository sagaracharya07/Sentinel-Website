"""Admin detection/incident/report-review APIs + access control."""

import pytest

from extensions import db
from models import Scan, EmailReport, AuditLog, Feedback, User


def _scan(
    scan_id,
    sender="a@ext.example",
    classification="Phishing",
    status="Quarantined",
    source="gmail",
    mailbox_action="quarantined",
):
    return Scan(
        scan_id=scan_id,
        sender=sender,
        subject="s",
        classification=classification,
        status=status,
        source=source,
        mailbox_action=mailbox_action,
    )


def _seed(app, scans):
    with app.app_context():
        for s in scans:
            db.session.add(s)
        db.session.commit()


ADMIN_ROUTES = [
    ("get", "/api/admin/detections"),
    ("get", "/api/admin/detections/quarantine"),
    ("get", "/api/admin/detections/needs-review"),
    ("get", "/api/admin/reports"),
]


# --- access control ----------------------------------------------------------
@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_routes_reject_normal_user(user_client, method, path):
    assert getattr(user_client, method)(path).status_code == 403


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_routes_reject_anonymous(client, method, path):
    assert getattr(client, method)(path).status_code == 401


def test_incident_and_related_reject_normal_user(user_client):
    assert user_client.get("/api/admin/detections/SCN-X").status_code == 403
    assert user_client.get("/api/admin/detections/SCN-X/related").status_code == 403


# --- detection lists ---------------------------------------------------------
def test_detections_list_and_source_filter(admin_client, app):
    _seed(
        app,
        [
            _scan("SCN-G1", source="gmail"),
            _scan(
                "SCN-U1",
                source="upload",
                status="Delivered",
                mailbox_action="none",
                classification="Legitimate",
            ),
        ],
    )
    all_rows = admin_client.get("/api/admin/detections").get_json()
    assert len(all_rows) == 2
    gmail_only = admin_client.get("/api/admin/detections?source=gmail").get_json()
    assert {r["scan_id"] for r in gmail_only} == {"SCN-G1"}


def test_quarantine_list_excludes_uploads(admin_client, app):
    _seed(
        app,
        [
            _scan("SCN-G1", source="gmail", status="Quarantined"),
            _scan(
                "SCN-U1", source="upload", status="Quarantined"
            ),  # upload, must be excluded
        ],
    )
    rows = admin_client.get("/api/admin/detections/quarantine").get_json()
    assert {r["scan_id"] for r in rows} == {"SCN-G1"}


def test_needs_review_list(admin_client, app):
    _seed(
        app,
        [
            _scan(
                "SCN-NR",
                classification="Needs Review",
                status="Flagged",
                mailbox_action="needs_review",
            ),
            _scan("SCN-P", classification="Phishing"),
        ],
    )
    rows = admin_client.get("/api/admin/detections/needs-review").get_json()
    assert {r["scan_id"] for r in rows} == {"SCN-NR"}


# --- incident detail + related ----------------------------------------------
def test_incident_detail_includes_timeline_and_related(admin_client, app):
    _seed(
        app,
        [
            _scan("SCN-1", sender="boss@corp.example"),
            _scan("SCN-2", sender="hr@corp.example"),  # same domain -> related
        ],
    )
    with app.app_context():
        db.session.add(
            AuditLog(actor="admin", action="gmail_quarantine", target="SCN-1")
        )
        db.session.commit()
    detail = admin_client.get("/api/admin/detections/SCN-1").get_json()
    assert detail["scan_id"] == "SCN-1"
    assert len(detail["timeline"]) == 1
    assert detail["related_count"] == 1


def test_incident_detail_404(admin_client):
    assert admin_client.get("/api/admin/detections/NOPE").status_code == 404


def test_related_search_returns_reasons(admin_client, app):
    _seed(
        app,
        [
            _scan("SCN-1", sender="boss@corp.example"),
            _scan("SCN-2", sender="boss@corp.example"),  # same sender
            _scan("SCN-3", sender="other@corp.example"),  # same domain
            _scan("SCN-4", sender="x@unrelated.example"),  # unrelated
        ],
    )
    body = admin_client.get("/api/admin/detections/SCN-1/related").get_json()
    ids = {r["scan_id"] for r in body["related"]}
    assert ids == {"SCN-2", "SCN-3"}
    reasons = {r["scan_id"]: r["related_reason"] for r in body["related"]}
    assert reasons["SCN-2"] == "same sender"
    assert "same domain" in reasons["SCN-3"]


# --- reported-email review ---------------------------------------------------
def _make_report(app, scan_id="SCN-R1"):
    with app.app_context():
        u = User(username="reporter", password_hash="x", role="user")
        db.session.add(u)
        db.session.commit()
        db.session.add(
            _scan(
                scan_id,
                source="upload",
                classification="Needs Review",
                status="Flagged",
            )
        )
        rep = EmailReport(
            reporter_user_id=u.id,
            reporter_username="reporter",
            scan_id=scan_id,
            status="pending",
        )
        db.session.add(rep)
        db.session.commit()
        return rep.id


def test_admin_reports_queue_lists_pending(admin_client, app):
    _make_report(app)
    rows = admin_client.get("/api/admin/reports?status=pending").get_json()
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"


def test_review_report_sets_verdict_and_feedback(admin_client, app):
    rid = _make_report(app)
    resp = admin_client.post(
        f"/api/admin/reports/{rid}/review", json={"verdict": "Phishing"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "reviewed"
    assert body["admin_verdict"] == "Phishing"
    assert body["reviewed_by"] == "test_admin"
    with app.app_context():
        assert (
            Feedback.query.filter_by(
                scan_id="SCN-R1", corrected_label="Phishing"
            ).count()
            == 1
        )


def test_review_rejects_invalid_verdict(admin_client, app):
    rid = _make_report(app)
    assert (
        admin_client.post(
            f"/api/admin/reports/{rid}/review", json={"verdict": "Maybe"}
        ).status_code
        == 400
    )


def test_review_requires_admin(user_client, app):
    rid = _make_report(app)
    assert (
        user_client.post(
            f"/api/admin/reports/{rid}/review", json={"verdict": "Phishing"}
        ).status_code
        == 403
    )
