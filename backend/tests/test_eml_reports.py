"""`.eml` upload + user-report ownership tests."""

from io import BytesIO
from email.message import EmailMessage

import pytest

from extensions import db
from models import EmailReport, Scan, User


def _eml(
    subject="Payroll update",
    body="please review http://evil.example/pay",
    sender="hr@ext.example",
):
    m = EmailMessage()
    m["From"] = sender
    m["Subject"] = subject
    m.set_content(body)
    return m.as_bytes()


def _upload(client, raw=None, filename="report.eml"):
    raw = raw if raw is not None else _eml()
    return client.post(
        "/api/reports/upload",
        data={"file": (BytesIO(raw), filename)},
        content_type="multipart/form-data",
    )


@pytest.fixture(autouse=True)
def _isolated_upload_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))


# --- upload ------------------------------------------------------------------
def test_upload_requires_login(client):
    assert _upload(client).status_code == 401


def test_valid_upload_creates_report_and_scan(user_client, app):
    resp = _upload(user_client)
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["status"] == "pending"
    assert body["scan"]["source"] == "upload"
    assert body["scan"]["classification"] in ("Phishing", "Needs Review", "Legitimate")
    with app.app_context():
        assert EmailReport.query.count() == 1
        assert Scan.query.filter_by(source="upload").count() == 1


def test_upload_rejects_non_eml_extension(user_client):
    resp = user_client.post(
        "/api/reports/upload",
        data={"file": (BytesIO(b"whatever"), "notes.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_upload_rejects_oversized_file(user_client, monkeypatch):
    monkeypatch.setenv("EML_MAX_BYTES", "50")
    resp = _upload(user_client, raw=_eml(body="x" * 500))
    assert resp.status_code == 400
    assert "too large" in resp.get_json()["error"].lower()


def test_upload_rejects_empty_file(user_client):
    resp = _upload(user_client, raw=b"")
    assert resp.status_code == 400


def test_upload_rejects_binary_junk(user_client):
    resp = _upload(user_client, raw=b"\x00\x01\x02\x03 no headers here")
    assert resp.status_code == 400


def test_upload_sanitises_filename(user_client, app):
    _upload(user_client, filename="../../../etc/passwd.eml")
    with app.app_context():
        report = EmailReport.query.first()
        assert "/" not in report.filename and ".." not in report.filename
        assert report.filename.endswith(".eml")


# --- ownership ---------------------------------------------------------------
def test_mine_shows_only_own_reports(user_client, app):
    _upload(user_client)
    # Create a report owned by a different user directly.
    with app.app_context():
        other = User(username="other_user", password_hash="x", role="user")
        db.session.add(other)
        db.session.commit()
        db.session.add(
            EmailReport(
                reporter_user_id=other.id,
                reporter_username="other_user",
                status="pending",
            )
        )
        db.session.commit()

    resp = user_client.get("/api/reports/mine")
    assert resp.status_code == 200
    usernames = {r["reporter_username"] for r in resp.get_json()}
    assert usernames == {"test_user"}


def test_report_detail_forbidden_for_other_user(user_client, app):
    with app.app_context():
        other = User(username="other2", password_hash="x", role="user")
        db.session.add(other)
        db.session.commit()
        rep = EmailReport(
            reporter_user_id=other.id, reporter_username="other2", status="pending"
        )
        db.session.add(rep)
        db.session.commit()
        rid = rep.id
    assert user_client.get(f"/api/reports/{rid}").status_code == 403


def test_report_detail_visible_to_admin(admin_client, app):
    with app.app_context():
        u = User(username="emp", password_hash="x", role="user")
        db.session.add(u)
        db.session.commit()
        rep = EmailReport(
            reporter_user_id=u.id, reporter_username="emp", status="pending"
        )
        db.session.add(rep)
        db.session.commit()
        rid = rep.id
    assert admin_client.get(f"/api/reports/{rid}").status_code == 200
