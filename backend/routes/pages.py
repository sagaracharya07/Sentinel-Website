"""
Front-end page routes for the revamped Sentinel console.

These render Jinja templates only — all data is fetched client-side from the
existing JSON APIs (routes/detections.py, routes/gmail.py, app.py). The value
they add over the old `TEMPLATE_PAGES` catch-all is **server-side access
control**: an admin page redirects an anonymous visitor to sign in and refuses
a non-admin with a 403, so the authenticated shells are never served to the
wrong audience (defence-in-depth on top of the APIs' own @admin_required).

No business logic lives here and no new data is produced; this is the frontend
routing layer for the security-operations revamp.
"""

from urllib.parse import quote

from flask import Blueprint, session, redirect, request, render_template, abort

pages_bp = Blueprint("pages", __name__)


def _login_redirect():
    return redirect("/login?next=" + quote(request.path, safe=""))


def _require_login():
    if not session.get("username"):
        return _login_redirect()
    return None


def _require_admin():
    if not session.get("username"):
        return _login_redirect()
    if session.get("role") != "admin":
        abort(403)
    return None


# ---------------------------------------------------------------------------
# Auth entry point (clean URL). The full auth redesign lands in a later
# checkpoint; for now this serves the existing login template so the new
# navigation's "Sign in" / sign-out links resolve to a working page.
# ---------------------------------------------------------------------------
@pages_bp.get("/login")
def login_page():
    if session.get("username"):
        return redirect("/admin" if session.get("role") == "admin" else "/app")
    return render_template("login.html")


# ---------------------------------------------------------------------------
# Administrator console (role=admin only)
# ---------------------------------------------------------------------------
@pages_bp.get("/admin")
def admin_overview():
    guard = _require_admin()
    if guard:
        return guard
    return render_template("admin/overview.html", active_nav="overview")


@pages_bp.get("/admin/detections")
def admin_detections():
    guard = _require_admin()
    if guard:
        return guard
    return render_template("admin/detections.html", active_nav="detections")


@pages_bp.get("/admin/detections/<scan_id>")
def admin_incident(scan_id):
    guard = _require_admin()
    if guard:
        return guard
    return render_template(
        "admin/incident.html", active_nav="detections", scan_id=scan_id
    )


@pages_bp.get("/admin/needs-review")
def admin_needs_review():
    guard = _require_admin()
    if guard:
        return guard
    return render_template("admin/needs_review.html", active_nav="needs-review")


@pages_bp.get("/admin/quarantine")
def admin_quarantine():
    guard = _require_admin()
    if guard:
        return guard
    return render_template("admin/quarantine.html", active_nav="quarantine")


@pages_bp.get("/admin/mailboxes")
def admin_mailboxes():
    guard = _require_admin()
    if guard:
        return guard
    return render_template("admin/mailboxes.html", active_nav="mailboxes")
