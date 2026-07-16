"""
Sentinel AI Phishing Detection Platform -- backend API.

Implements the server-end functional requirements from the proposal
(Section 2.2 FR-SE-01..12) and database requirements (Section 2.3
FR-DB-01..08) as a real Flask + SQLite service, replacing the client-only
localStorage/heuristic build. Also serves the existing front-end
(site/) as static files so the whole platform runs from one process.

Run:
    cd backend
    python3 app.py
Then open http://localhost:5000
"""
import os
import json
import random
import string
import threading
import time
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
load_dotenv()  # loads backend/.env if present (real mailbox credentials, secret key, etc.)

from flask import Flask, request, jsonify, session, send_from_directory
from werkzeug.security import generate_password_hash

from extensions import db
from models import Scan, Feedback, ModelVersion, AuditLog, User, MailboxStatus
from auth import verify_login, login_required, admin_required, current_actor, log_action
from ml import infer
from ml import train as train_module
from mailbox.imap_client import MailboxConfig, MailboxError, test_connection as mailbox_test_connection
from mailbox.sync import sync_mailbox

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "..", "site")
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

app = Flask(__name__, static_folder=None)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(INSTANCE_DIR, "sentinel.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SENTINEL_SECRET_KEY", "dev-secret-change-in-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db.init_app(app)

RETENTION_HOURS = 24  # FR-DB-05 / NFR-Security: don't keep raw bodies indefinitely


# ---------------------------------------------------------------------------
# Security headers (TLS itself is a deployment/reverse-proxy concern -- see
# README -- but these are real, applied on every response)
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


# ---------------------------------------------------------------------------
# Static front-end (index.html, scan.html, admin.html, login.html, css/js)
# ---------------------------------------------------------------------------
@app.route("/")
def root():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    full = os.path.join(STATIC_DIR, filename)
    if os.path.isfile(full):
        return send_from_directory(STATIC_DIR, filename)
    return jsonify({"error": "not found"}), 404


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def new_scan_id():
    return "SCN-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def status_for(label, risk_level):
    if label == "Phishing":
        return "Quarantined" if risk_level == "High" else "Flagged"
    return "Delivered"


def purge_old_bodies():
    """FR-DB-05: minimise/anonymise sensitive content in storage. Real
    background job (not just a claim in the docs) that redacts email
    bodies once they pass the retention window, keeping only the
    classification metadata needed for auditing/reporting."""
    with app.app_context():
        cutoff = datetime.now(timezone.utc) - timedelta(hours=RETENTION_HOURS)
        cutoff_naive = cutoff.replace(tzinfo=None)
        old = Scan.query.filter(Scan.scan_timestamp < cutoff_naive, Scan.body_purged.is_(False)).all()
        for s in old:
            s.body = None
            s.body_purged = True
        if old:
            db.session.commit()
            log_action("system", "privacy_purge", details=f"Purged {len(old)} scan bodies older than {RETENTION_HOURS}h")


def purge_loop():
    while True:
        try:
            purge_old_bodies()
        except Exception as e:
            print("purge_loop error:", e)
        time.sleep(600)  # every 10 minutes


def mailbox_poll_loop():
    """
    Continuously watches the configured real mailbox and scans new mail
    automatically -- this is what makes scanning 'automatic' rather than
    something a user has to manually trigger every time. If no mailbox is
    configured (.env not set up), each pass is a fast no-op.
    """
    interval = int(os.environ.get("MAILBOX_POLL_SECONDS", "45"))
    while True:
        try:
            with app.app_context():
                sync_mailbox(log_action=log_action)
        except Exception as e:
            print("mailbox_poll_loop error:", e)
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Public marketing-page demo (no login) -- runs the SAME real model as
# everywhere else, so even the homepage hero animation reflects the actual
# trained classifier rather than a hardcoded/fake number.
# ---------------------------------------------------------------------------
DEMO_SAMPLE = dict(
    subject="Your account will be suspended — verify now",
    sender="PayPal Security <security@paypa1-support.com>",
    body="Dear Customer, we detected unusual activity. Verify your account immediately "
         "or it will be suspended within 24 hours. Click here: http://bit.ly/verify-acct",
)


@app.get("/api/public/demo-scan")
def public_demo_scan():
    result = infer.classify(DEMO_SAMPLE["subject"], DEMO_SAMPLE["body"], DEMO_SAMPLE["sender"])
    result["subject"] = DEMO_SAMPLE["subject"]
    result["body"] = DEMO_SAMPLE["body"]
    result["from"] = DEMO_SAMPLE["sender"]
    return jsonify(result)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = verify_login(username, password)
    if not user:
        log_action(username or "unknown", "login_failed")
        return jsonify({"error": "Invalid username or password"}), 401
    session["username"] = user.username
    session["role"] = user.role
    log_action(user.username, "login_success")
    return jsonify(user.to_public())


@app.post("/api/auth/logout")
def logout():
    actor = current_actor()
    session.clear()
    log_action(actor, "logout")
    return jsonify({"ok": True})


@app.get("/api/auth/me")
def me():
    if not session.get("username"):
        return jsonify({"error": "not authenticated"}), 401
    return jsonify({"username": session["username"], "role": session["role"]})


# ---------------------------------------------------------------------------
# Scanning (FR-SE-01..12, FR-FE-01..08)
# ---------------------------------------------------------------------------
@app.post("/api/scan")
@login_required
def scan_email():
    data = request.get_json(silent=True) or {}
    subject = (data.get("subject") or "").strip()
    body = (data.get("body") or "").strip()
    sender = (data.get("from") or "").strip()

    if not body:
        return jsonify({"error": "Email body is required"}), 400
    if len(body) > 20000:
        return jsonify({"error": "Email body too large (max 20,000 characters)"}), 400

    result = infer.classify(subject, body, sender)
    status = status_for(result["label"], result["risk_level"])

    scan = Scan(
        scan_id=new_scan_id(),
        sender=sender or "(unknown sender)",
        subject=subject or "(no subject)",
        body=body,
        classification=result["label"],
        confidence_score=result["confidence"],
        score=result["score"],
        risk_level=result["risk_level"],
        findings_json=json.dumps(result["findings"]),
        highlights_json=json.dumps(result["highlights"]),
        status=status,
        model_version=result["model_version"],
        created_by=current_actor(),
    )
    db.session.add(scan)
    db.session.commit()
    log_action(current_actor(), "scan", target=scan.scan_id,
               details=f"{result['label']} ({result['score']}/100)")
    return jsonify(scan.to_dict())


@app.get("/api/history")
@login_required
def history():
    mine_only = request.args.get("mine", "false").lower() == "true"
    status_filter = request.args.get("status")
    limit = min(int(request.args.get("limit", 100)), 500)

    q = Scan.query
    if mine_only and session.get("role") != "admin":
        q = q.filter(Scan.created_by == session["username"])
    if status_filter and status_filter != "All":
        q = q.filter(Scan.status == status_filter)
    scans = q.order_by(Scan.scan_timestamp.desc()).limit(limit).all()
    return jsonify([s.to_dict() for s in scans])


@app.get("/api/scan/<scan_id>")
@login_required
def get_scan(scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    if session.get("role") != "admin" and scan.created_by != session["username"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(scan.to_dict())


@app.get("/api/stats")
@login_required
def stats():
    scans = Scan.query.all()
    total = len(scans)
    phishing = sum(1 for s in scans if s.classification == "Phishing")
    quarantined = sum(1 for s in scans if s.status == "Quarantined")
    flagged = sum(1 for s in scans if s.status == "Flagged")
    avg_conf = (sum(s.confidence_score or 0 for s in scans) / total) if total else 0
    return jsonify({
        "total": total, "phishing": phishing, "legitimate": total - phishing,
        "quarantined": quarantined, "flagged": flagged, "avg_confidence": avg_conf,
    })


# ---------------------------------------------------------------------------
# Feedback (UC-05, FR-DB-07) & admin actions (UC-04)
# ---------------------------------------------------------------------------
@app.post("/api/feedback")
@login_required
def submit_feedback():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    corrected_label = data.get("corrected_label")
    if corrected_label not in ("Phishing", "Legitimate"):
        return jsonify({"error": "corrected_label must be 'Phishing' or 'Legitimate'"}), 400

    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404

    fb = Feedback(scan_id=scan_id, original_label=scan.classification,
                  corrected_label=corrected_label, submitted_by=current_actor())
    db.session.add(fb)
    scan.user_feedback = corrected_label
    scan.notes = f"User corrected to: {corrected_label}"
    db.session.commit()
    log_action(current_actor(), "feedback_submitted", target=scan_id,
               details=f"{scan.classification} -> {corrected_label}")
    return jsonify(scan.to_dict())


@app.post("/api/admin/action")
@admin_required
def admin_action():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    action = data.get("action")  # release | confirm | escalate
    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404

    if action == "release":
        scan.status = "Delivered"
        scan.notes = "Released by admin — marked false positive"
        fb = Feedback(scan_id=scan_id, original_label=scan.classification,
                      corrected_label="Legitimate", submitted_by=current_actor())
        db.session.add(fb)
        scan.user_feedback = "Legitimate"

        # If this came from the real mailbox and was actually quarantined
        # there, move it back to the inbox for real -- otherwise "release"
        # would only be true in our database, not in the actual mailbox.
        if scan.source == "mailbox" and scan.mailbox_action == "quarantined":
            cfg = MailboxConfig.from_env()
            if cfg:
                try:
                    from mailbox.imap_client import unquarantine_message
                    unquarantine_message(cfg, scan.mailbox_message_id)
                    scan.mailbox_action = "none"
                    scan.mailbox_action_error = None
                    scan.notes += " (moved back to inbox)"
                except MailboxError as e:
                    scan.mailbox_action_error = f"Release-to-inbox failed: {e}"
    elif action == "confirm":
        scan.notes = "Confirmed phishing by admin"
        fb = Feedback(scan_id=scan_id, original_label=scan.classification,
                      corrected_label="Phishing", submitted_by=current_actor())
        db.session.add(fb)
        scan.user_feedback = "Phishing"
    elif action == "escalate":
        scan.notes = "Escalated for further investigation"
    else:
        return jsonify({"error": "unknown action"}), 400

    db.session.commit()
    log_action(current_actor(), f"admin_{action}", target=scan_id, details=scan.notes)
    return jsonify(scan.to_dict())


# ---------------------------------------------------------------------------
# Model info & retraining (UC-07, pseudocode 6.9, NFR-Maintainability)
# ---------------------------------------------------------------------------
@app.get("/api/admin/model-info")
@admin_required
def model_info():
    current = infer.current_info()
    versions = ModelVersion.query.order_by(ModelVersion.trained_at.desc()).all()
    pending_feedback = Feedback.query.filter_by(used_in_retrain=False).count()
    return jsonify({
        "current": current,
        "versions": [v.to_dict() for v in versions],
        "pending_feedback_count": pending_feedback,
    })


@app.post("/api/admin/retrain")
@admin_required
def retrain():
    import pandas as pd

    pending = Feedback.query.filter_by(used_in_retrain=False).all()
    rows = []
    for fb in pending:
        scan = Scan.query.get(fb.scan_id)
        if not scan or scan.body_purged or not scan.body:
            continue
        rows.append({
            "sender": scan.sender or "",
            "subject": scan.subject or "",
            "body": scan.body or "",
            "label": 1 if fb.corrected_label == "Phishing" else 0,
        })

    extra_df = pd.DataFrame(rows) if rows else None
    notes = f"Retrained with {len(rows)} confirmed feedback correction(s)"
    version, metrics, meta = train_module.train(extra_df=extra_df, notes=notes)

    ModelVersion.query.update({ModelVersion.is_current: False})
    mv = ModelVersion(
        version=version, accuracy=metrics["accuracy"], precision=metrics["precision"],
        recall=metrics["recall"], f1_score=metrics["f1_score"],
        false_positive_rate=metrics["false_positive_rate"],
        false_negative_rate=metrics["false_negative_rate"],
        n_train=metrics["n_train"], n_test=metrics["n_test"],
        n_feedback_folded_in=len(rows), notes=notes, is_current=True,
    )
    db.session.add(mv)
    for fb in pending:
        fb.used_in_retrain = True
    db.session.commit()

    infer.reload()
    log_action(current_actor(), "retrain_model", target=version, details=notes)
    return jsonify({"version": version, "metrics": metrics, "meta": meta})


@app.get("/api/admin/audit-log")
@admin_required
def audit_log():
    limit = min(int(request.args.get("limit", 100)), 500)
    entries = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return jsonify([e.to_dict() for e in entries])


# ---------------------------------------------------------------------------
# Live mailbox integration (real IMAP connection, not copy-paste)
# ---------------------------------------------------------------------------
@app.get("/api/admin/mailbox-status")
@admin_required
def mailbox_status():
    row = db.session.get(MailboxStatus, 1)
    if not row:
        cfg = MailboxConfig.from_env()
        return jsonify({
            "configured": cfg is not None, "connected": False, "last_sync_at": None,
            "last_error": None, "last_new_messages": 0, "total_synced": 0,
            "host": cfg.host if cfg else None, "username": cfg.username if cfg else None,
            "inbox_folder": cfg.inbox_folder if cfg else None,
            "quarantine_folder": cfg.quarantine_folder if cfg else None,
        })
    return jsonify(row.to_dict())


@app.post("/api/admin/mailbox-test")
@admin_required
def mailbox_test():
    cfg = MailboxConfig.from_env()
    if not cfg:
        return jsonify({"ok": False, "error": "Mailbox not configured — set MAILBOX_HOST / "
                                                "MAILBOX_USERNAME / MAILBOX_PASSWORD in backend/.env "
                                                "(see backend/.env.example)"}), 400
    result = mailbox_test_connection(cfg)
    log_action(current_actor(), "mailbox_test", details=json.dumps(result))
    return jsonify(result)


@app.post("/api/admin/mailbox-sync")
@admin_required
def mailbox_sync_now():
    result = sync_mailbox(log_action=log_action)
    return jsonify(result)


@app.post("/api/admin/reset-demo-data")
@admin_required
def reset_demo_data():
    from seed_db import seed_demo_scans
    Feedback.query.delete()
    Scan.query.delete()
    db.session.commit()
    seed_demo_scans()
    log_action(current_actor(), "reset_demo_data")
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
def ensure_seed_data():
    from seed_db import seed_users, seed_demo_scans, seed_model_version_row
    db.create_all()
    seed_users()
    seed_model_version_row()
    if Scan.query.count() == 0:
        seed_demo_scans()


if __name__ == "__main__":
    with app.app_context():
        ensure_seed_data()
    threading.Thread(target=purge_loop, daemon=True).start()
    threading.Thread(target=mailbox_poll_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)
