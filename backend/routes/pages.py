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


@pages_bp.get("/signup")
def signup_page():
    if session.get("username"):
        return redirect("/admin" if session.get("role") == "admin" else "/app")
    return render_template("signup.html")


@pages_bp.get("/forgot-password")
def forgot_password_page():
    return render_template("forgot-password.html")


@pages_bp.get("/reset-password")
def reset_password_page():
    return render_template("reset-password.html")


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


# ---------------------------------------------------------------------------
# User portal (any authenticated user -- employees and administrators alike;
# an administrator can still report a suspicious email themselves)
# ---------------------------------------------------------------------------
@pages_bp.get("/app")
def portal_overview():
    guard = _require_login()
    if guard:
        return guard
    return render_template("portal/overview.html", active_nav="overview")


@pages_bp.get("/app/report")
def portal_report():
    guard = _require_login()
    if guard:
        return guard
    return render_template("portal/report.html", active_nav="report")


@pages_bp.get("/app/reports")
def portal_reports():
    guard = _require_login()
    if guard:
        return guard
    return render_template("portal/reports.html", active_nav="reports")


@pages_bp.get("/app/reports/<int:report_id>")
def portal_report_detail(report_id):
    guard = _require_login()
    if guard:
        return guard
    return render_template(
        "portal/report_detail.html", active_nav="reports", report_id=report_id
    )


@pages_bp.get("/app/quick-analysis")
def portal_quick_analysis():
    guard = _require_login()
    if guard:
        return guard
    return render_template("portal/quick_analysis.html", active_nav="quick")


@pages_bp.get("/app/guide")
def portal_guide():
    guard = _require_login()
    if guard:
        return guard
    return render_template("portal/guide.html", active_nav="guide")


@pages_bp.get("/app/account")
def portal_account():
    guard = _require_login()
    if guard:
        return guard
    return render_template("portal/account.html", active_nav="account")


@pages_bp.get("/app/preferences")
def portal_preferences():
    guard = _require_login()
    if guard:
        return guard
    return render_template("portal/preferences.html", active_nav="preferences")


# ---------------------------------------------------------------------------
# Public marketing website. Static content only -- no auth, no per-request
# data (the one exception, the public demo-scan endpoint used by the Live
# Demo page, already existed before this revamp). `active_page` drives the
# nav's active-link highlight (see partials/_nav_public.html).
# ---------------------------------------------------------------------------
@pages_bp.get("/product")
def public_product():
    return render_template("public/product.html", active_page="product")


@pages_bp.get("/how-it-works")
def public_how_it_works():
    return render_template("public/how_it_works.html", active_page="how-it-works")


@pages_bp.get("/integrations")
def public_integrations():
    return render_template("public/integrations.html", active_page="integrations")


@pages_bp.get("/demo")
def public_demo():
    return render_template("public/demo.html", active_page="demo")


@pages_bp.get("/threat-lab")
def public_threat_lab():
    return render_template("public/threat_lab.html", active_page="threat-lab")


@pages_bp.get("/security")
def public_security():
    return render_template("public/security.html", active_page="security")


@pages_bp.get("/about")
def public_about():
    return render_template("public/about.html", active_page="about")


@pages_bp.get("/help")
def public_help():
    return render_template("public/help.html", active_page="help")


@pages_bp.get("/faq")
def public_faq():
    return render_template("public/faq.html", active_page="faq")


@pages_bp.get("/contact")
def public_contact():
    return render_template("public/contact.html", active_page="contact")


@pages_bp.get("/terms")
def public_terms():
    return render_template("public/terms.html", active_page="terms")


@pages_bp.get("/privacy")
def public_privacy():
    return render_template("public/privacy.html", active_page="privacy")
