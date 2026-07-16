"""
Authentication for the Sentinel AI platform.

Implements FR: "role-based authentication" restricting admin features
(NFR-Security). Uses Flask's signed session cookie (server-side secret,
HttpOnly by default) plus Werkzeug password hashing -- no plaintext
passwords are ever stored or logged. This is intentionally simple
(no OAuth/SSO) which is appropriate for an academic capstone scope, but
real hashing + real session-based access control, not a cosmetic login
screen.
"""
from functools import wraps
from flask import session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db
from models import User, AuditLog


def create_user(username, password, role="user"):
    u = User(username=username, password_hash=generate_password_hash(password), role=role)
    db.session.add(u)
    db.session.commit()
    return u


def verify_login(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        return user
    return None


def log_action(actor, action, target="", details=""):
    entry = AuditLog(actor=actor, action=action, target=target, details=details)
    db.session.add(entry)
    db.session.commit()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return jsonify({"error": "Authentication required"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin role required"}), 403
        return fn(*args, **kwargs)
    return wrapper


def current_actor():
    return session.get("username", "anonymous")
