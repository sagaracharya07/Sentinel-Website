"""
Administrator detection & incident APIs (admin-only).

Covers the reported-email queue + review, detection lists with filters,
incident detail (with event timeline + related count), and a basic
related-message search. Normal users never reach these -- every route is
@admin_required, and organisation-wide detections are admin-only by design.
"""

import re
import logging
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify

from extensions import db
from auth import admin_required, current_actor, log_action
from models import Scan, EmailReport, Feedback, AuditLog

logger = logging.getLogger(__name__)

detections_bp = Blueprint("detections", __name__)

_VALID_SOURCES = {"gmail", "upload", "mailbox", "manual"}


def _limit(default=100, cap=500):
    try:
        return min(int(request.args.get("limit", default)), cap)
    except (TypeError, ValueError):
        return default


def _sender_domain(sender: str) -> str:
    m = re.search(r"@([\w.\-]+)", (sender or "").lower())
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# reported-email queue + review
# ---------------------------------------------------------------------------
@detections_bp.get("/api/admin/reports")
@admin_required
def admin_reports():
    status = request.args.get("status")
    q = EmailReport.query
    if status in ("pending", "reviewed"):
        q = q.filter_by(status=status)
    rows = q.order_by(EmailReport.created_at.desc()).limit(_limit()).all()
    out = []
    for r in rows:
        scan = db.session.get(Scan, r.scan_id) if r.scan_id else None
        out.append(r.to_dict(scan=scan))
    return jsonify(out)


@detections_bp.post("/api/admin/reports/<int:report_id>/review")
@admin_required
def review_report(report_id):
    data = request.get_json(silent=True) or {}
    verdict = data.get("verdict")
    if verdict not in ("Phishing", "Legitimate"):
        return jsonify({"error": "verdict must be 'Phishing' or 'Legitimate'"}), 400

    report = db.session.get(EmailReport, report_id)
    if not report:
        return jsonify({"error": "report not found"}), 404

    report.admin_verdict = verdict
    report.status = "reviewed"
    report.reviewed_by = current_actor()
    report.reviewed_at = datetime.now(timezone.utc).replace(tzinfo=None)

    scan = db.session.get(Scan, report.scan_id) if report.scan_id else None
    if scan:
        db.session.add(
            Feedback(
                scan_id=scan.scan_id,
                original_label=scan.classification,
                corrected_label=verdict,
                submitted_by=current_actor(),
            )
        )
        scan.user_feedback = verdict
    db.session.commit()

    log_action(
        current_actor(), "report_reviewed", target=report.scan_id, details=verdict
    )
    return jsonify(report.to_dict(scan=scan))


# ---------------------------------------------------------------------------
# detection lists
# ---------------------------------------------------------------------------
def _apply_filters(q):
    args = request.args
    source = args.get("source")
    if source in _VALID_SOURCES:
        q = q.filter(Scan.source == source)
    if args.get("classification") and args["classification"] != "All":
        q = q.filter(Scan.classification == args["classification"])
    if args.get("status") and args["status"] != "All":
        q = q.filter(Scan.status == args["status"])
    if args.get("mailbox_action"):
        q = q.filter(Scan.mailbox_action == args["mailbox_action"])
    if args.get("risk_level"):
        q = q.filter(Scan.risk_level == args["risk_level"])
    if args.get("sender"):
        q = q.filter(Scan.sender.like(f"%{args['sender']}%"))
    if args.get("subject"):
        q = q.filter(Scan.subject.like(f"%{args['subject']}%"))
    return q


@detections_bp.get("/api/admin/detections")
@admin_required
def detections():
    q = _apply_filters(Scan.query)
    rows = q.order_by(Scan.scan_timestamp.desc()).limit(_limit()).all()
    return jsonify([s.to_dict() for s in rows])


@detections_bp.get("/api/admin/detections/quarantine")
@admin_required
def quarantine_list():
    # Real mailbox quarantine only (Gmail/IMAP) -- uploads/manual scans aren't
    # in a mailbox, so they don't belong on this operational queue.
    rows = (
        Scan.query.filter(Scan.status == "Quarantined")
        .filter(Scan.source.in_(("gmail", "mailbox")))
        .order_by(Scan.scan_timestamp.desc())
        .limit(_limit())
        .all()
    )
    return jsonify([s.to_dict() for s in rows])


@detections_bp.get("/api/admin/detections/needs-review")
@admin_required
def needs_review_list():
    rows = (
        Scan.query.filter(Scan.classification == "Needs Review")
        .order_by(Scan.scan_timestamp.desc())
        .limit(_limit())
        .all()
    )
    return jsonify([s.to_dict() for s in rows])


# ---------------------------------------------------------------------------
# incident detail + related search
# ---------------------------------------------------------------------------
def _related_query(scan):
    """Scans related to `scan` by exact sender or same sender domain. Basic by
    design (Phase 10) -- enough to spot a campaign, not a full correlation
    engine. Excludes the scan itself."""
    domain = _sender_domain(scan.sender)
    q = Scan.query.filter(Scan.scan_id != scan.scan_id)
    if domain:
        q = q.filter(
            db.or_(Scan.sender == scan.sender, Scan.sender.like(f"%@{domain}%"))
        )
    else:
        q = q.filter(Scan.sender == scan.sender)
    return q


@detections_bp.get("/api/admin/detections/<scan_id>")
@admin_required
def incident_detail(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404

    timeline = [
        e.to_dict()
        for e in AuditLog.query.filter_by(target=scan_id)
        .order_by(AuditLog.timestamp.asc())
        .all()
    ]
    related_count = _related_query(scan).count()

    detail = scan.to_dict()
    detail["timeline"] = timeline
    detail["related_count"] = related_count
    # Link back to a user report, if this detection came from an upload.
    report = EmailReport.query.filter_by(scan_id=scan_id).first()
    detail["report"] = report.to_dict() if report else None
    return jsonify(detail)


@detections_bp.get("/api/admin/detections/<scan_id>/related")
@admin_required
def related(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    domain = _sender_domain(scan.sender)
    rows = _related_query(scan).order_by(Scan.scan_timestamp.desc()).limit(50).all()
    out = []
    for s in rows:
        reason = "same sender" if s.sender == scan.sender else f"same domain ({domain})"
        item = s.to_dict()
        item["related_reason"] = reason
        out.append(item)
    return jsonify({"count": len(out), "related": out})
