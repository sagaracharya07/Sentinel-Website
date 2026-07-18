"""
Users & Roles administration (admin-only).

Small, deliberately narrow addition approved in the frontend-revamp
Checkpoint 0 direction: the console needs a real way to list users, change a
role, and suspend/reactivate an account -- none of which existed before.
Password hashes and tokens are never returned (see User.to_admin_dict()).

Safety rules enforced here, not just in the UI:
  - the last remaining admin can never be demoted or suspended (would lock
    the whole console out with no way back in)
  - every change is written to the audit log
  - suspension is reversible (User.is_active flips back), never a delete
"""

import logging

from flask import Blueprint, request, jsonify

from extensions import db
from auth import admin_required, current_actor, log_action
from models import User

logger = logging.getLogger(__name__)

users_bp = Blueprint("users", __name__)

_VALID_ROLES = {"user", "admin"}


def _active_admin_count(exclude_id=None):
    q = User.query.filter_by(role="admin", is_active=True)
    if exclude_id is not None:
        q = q.filter(User.id != exclude_id)
    return q.count()


@users_bp.get("/api/admin/users")
@admin_required
def list_users():
    role = request.args.get("role")
    q = User.query
    if role in _VALID_ROLES:
        q = q.filter_by(role=role)
    search = (request.args.get("search") or "").strip()
    if search:
        q = q.filter(User.username.ilike(f"%{search}%"))
    users = q.order_by(User.created_at.desc()).all()
    return jsonify([u.to_admin_dict() for u in users])


@users_bp.post("/api/admin/users/<int:user_id>/role")
@admin_required
def change_role(user_id):
    data = request.get_json(silent=True) or {}
    new_role = data.get("role")
    if new_role not in _VALID_ROLES:
        return jsonify({"error": "role must be 'user' or 'admin'"}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404

    if (
        user.role == "admin"
        and new_role == "user"
        and _active_admin_count(exclude_id=user.id) == 0
    ):
        return jsonify({"error": "Cannot demote the last remaining administrator"}), 400

    old_role = user.role
    user.role = new_role
    db.session.commit()
    log_action(
        current_actor(),
        "user_role_changed",
        target=user.username,
        details=f"{old_role} -> {new_role}",
    )
    return jsonify(user.to_admin_dict())


@users_bp.post("/api/admin/users/<int:user_id>/suspend")
@admin_required
def suspend_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404

    if user.role == "admin" and _active_admin_count(exclude_id=user.id) == 0:
        return jsonify(
            {"error": "Cannot suspend the last remaining administrator"}
        ), 400

    user.is_active = False
    db.session.commit()
    log_action(current_actor(), "user_suspended", target=user.username)
    return jsonify(user.to_admin_dict())


@users_bp.post("/api/admin/users/<int:user_id>/activate")
@admin_required
def activate_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404

    user.is_active = True
    db.session.commit()
    log_action(current_actor(), "user_activated", target=user.username)
    return jsonify(user.to_admin_dict())
