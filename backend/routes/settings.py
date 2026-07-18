"""
Detection Policy settings (admin-only).

The one genuinely writable Settings page from the frontend-revamp direction
(Checkpoint 0's approved additions): the Needs-Review / Phishing probability
cut points used by ml/infer.decide() were previously fixed code constants
(0.50 / 0.75) with no way to adjust them short of a redeploy. This exposes
them as a single admin-configurable row (models.AppSettings), validated,
audited, and confirmed client-side before changing live classification
behaviour.

This does NOT retrain or replace the model -- it only changes where the
probability line is drawn for an already-computed phishing_probability.
"""

import logging

from flask import Blueprint, request, jsonify

from extensions import db
from auth import admin_required, current_actor, log_action
from models import AppSettings

logger = logging.getLogger(__name__)

settings_bp = Blueprint("settings", __name__)


@settings_bp.get("/api/admin/settings/detection-policy")
@admin_required
def get_detection_policy():
    return jsonify(AppSettings.current().to_dict())


@settings_bp.post("/api/admin/settings/detection-policy")
@admin_required
def update_detection_policy():
    data = request.get_json(silent=True) or {}
    try:
        needs_review = float(data.get("needs_review_threshold"))
        phishing = float(data.get("phishing_threshold"))
    except (TypeError, ValueError):
        return jsonify({"error": "Both thresholds must be numbers"}), 400

    if not (0.0 < needs_review < phishing < 1.0):
        return jsonify(
            {
                "error": "Thresholds must satisfy 0 < Needs Review threshold < "
                "Phishing threshold < 1"
            }
        ), 400

    row = AppSettings.current()
    old = row.to_dict()
    row.needs_review_threshold = needs_review
    row.phishing_threshold = phishing
    row.updated_by = current_actor()
    db.session.commit()

    log_action(
        current_actor(),
        "detection_policy_updated",
        details=(
            f"needs_review {old['needs_review_threshold']}->{needs_review}, "
            f"phishing {old['phishing_threshold']}->{phishing}"
        ),
    )
    return jsonify(row.to_dict())
