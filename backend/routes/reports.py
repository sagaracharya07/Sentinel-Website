"""
Employee `.eml` reporting routes (any authenticated user).

Ownership is strict: a user can upload a report and view only their own
reports. Administrator review lives in routes/detections.py.
"""

import logging

from flask import Blueprint, request, jsonify, session

from extensions import db, limiter
from auth import login_required, log_action
from models import User, EmailReport, Scan
from reports import eml

logger = logging.getLogger(__name__)

reports_bp = Blueprint("reports", __name__)


def _report_with_scan(report):
    scan = db.session.get(Scan, report.scan_id) if report.scan_id else None
    return report.to_dict(scan=scan)


@reports_bp.post("/api/reports/upload")
@login_required
@limiter.limit("20 per hour")
def upload():
    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded (expected form field 'file')"}), 400

    try:
        raw, safe = eml.validate_and_read(request.files["file"])
        report, scan = eml.analyze_and_store(user, raw, safe)
    except eml.EmlValidationError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        logger.exception("eml upload failed")
        return jsonify({"error": "Could not process the uploaded email"}), 500

    log_action(user.username, "report_uploaded", target=report.scan_id, details=safe)
    return jsonify(report.to_dict(scan=scan)), 201


@reports_bp.get("/api/reports/mine")
@login_required
def mine():
    reports = (
        EmailReport.query.filter_by(reporter_username=session["username"])
        .order_by(EmailReport.created_at.desc())
        .limit(200)
        .all()
    )
    return jsonify([_report_with_scan(r) for r in reports])


@reports_bp.get("/api/reports/<int:report_id>")
@login_required
def detail(report_id):
    report = db.session.get(EmailReport, report_id)
    if not report:
        return jsonify({"error": "not found"}), 404
    # Ownership: a normal user may only see their own report; admins see any.
    if (
        session.get("role") != "admin"
        and report.reporter_username != session["username"]
    ):
        return jsonify({"error": "forbidden"}), 403
    return jsonify(_report_with_scan(report))
