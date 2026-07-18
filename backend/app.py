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
import re
import html
import json
import random
import string
import logging
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()  # loads backend/.env if present (real mailbox credentials, secret key, etc.)

from flask import (
    Flask,
    request,
    jsonify,
    session,
    send_from_directory,
    redirect,
    render_template,
)
from flask_wtf.csrf import generate_csrf
from werkzeug.security import generate_password_hash

from extensions import db, csrf, limiter
from models import Scan, Feedback, ModelVersion, AuditLog, User, MailboxStatus
from auth import (
    verify_login,
    login_required,
    admin_required,
    current_actor,
    log_action,
    create_user,
    generate_token,
)
from ml import infer
from mailbox.imap_client import (
    MailboxConfig,
    MailboxError,
    test_connection as mailbox_test_connection,
)
from mailbox.sync import sync_mailbox
from db_config import resolve_database_uri
from mail.email_client import send_email, public_base_url
from logging_config import configure_logging
from monitoring import init_sentry

configure_logging()
logger = logging.getLogger(__name__)

# No-op unless SENTRY_DSN is set -- see monitoring.py.
from sentry_sdk.integrations.flask import FlaskIntegration

init_sentry(extra_integrations=[FlaskIntegration()])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "..", "site")
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

# SENTINEL_ENV gates every dev-convenience default (insecure secret key,
# demo account/data seeding) so a production boot can never silently fall
# back to something meant only for local development.
SENTINEL_ENV = os.environ.get("SENTINEL_ENV", "development").strip().lower()
IS_PRODUCTION = SENTINEL_ENV == "production"

app = Flask(__name__, static_folder=None)
app.config["SQLALCHEMY_DATABASE_URI"] = resolve_database_uri(
    INSTANCE_DIR, IS_PRODUCTION
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

_INSECURE_DEFAULT_SECRET = "dev-secret-change-in-production"
_secret_key = os.environ.get("SENTINEL_SECRET_KEY")
if IS_PRODUCTION and (not _secret_key or _secret_key == _INSECURE_DEFAULT_SECRET):
    # Reject both an unset key AND the well-known placeholder value from
    # .env.example -- copying that file verbatim into a real .env must not
    # silently satisfy this check.
    raise RuntimeError(
        "SENTINEL_SECRET_KEY must be set to a real, unique secret when "
        "SENTINEL_ENV=production -- refusing to start with an insecure or "
        "default secret key."
    )
if not _secret_key:
    _secret_key = _INSECURE_DEFAULT_SECRET
app.config["SECRET_KEY"] = _secret_key

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION

# Rate limiting -- shared via Redis (same instance Celery uses) so limits
# apply across all web replicas instead of being tracked per-process, which
# would let an attacker bypass the limit just by landing on a different
# instance. Falls back to in-memory storage if REDIS_URL isn't set (local
# dev without Redis running), with a warning from flask-limiter itself.
_redis_url = os.environ.get("REDIS_URL")
if _redis_url:
    app.config["RATELIMIT_STORAGE_URI"] = _redis_url

# Extensions are constructed unbound in extensions.py (so blueprints can
# import them without importing app.py) and bound here via init_app().
#
# CSRF protection -- the session cookie is the only thing authenticating
# API requests (see site/js/api.js: `credentials: 'same-origin'`, no
# bearer token), which makes every state-changing (POST/PUT/PATCH/DELETE)
# route vulnerable to CSRF without this: a malicious page could submit a
# cross-site request and the browser would attach the victim's session
# cookie automatically. CSRFProtect checks all unsafe-method requests by
# default (GET/HEAD/OPTIONS are inherently exempt), so this covers every
# POST route uniformly rather than a hand-picked subset. The frontend
# fetches a token from GET /api/csrf-token (below) and sends it back as
# the X-CSRFToken header -- see site/js/api.js's request().
db.init_app(app)
csrf.init_app(app)
limiter.init_app(app)

# Gmail OAuth / connected-mailbox routes live in a blueprint (routes/gmail.py)
# rather than inline here -- the Gmail integration adds enough endpoints that
# piling them into this already-large module would be unmaintainable. The
# blueprint imports only shared extensions/auth/models, never app.py, so this
# registration is import-cycle-free.
from routes.gmail import gmail_bp  # noqa: E402
from routes.reports import reports_bp  # noqa: E402
from routes.detections import detections_bp  # noqa: E402
from routes.pubsub import pubsub_bp  # noqa: E402
from routes.pages import pages_bp  # noqa: E402
from routes.users import users_bp  # noqa: E402
from routes.system import system_bp  # noqa: E402
from routes.settings import settings_bp  # noqa: E402

app.register_blueprint(gmail_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(detections_bp)
app.register_blueprint(pubsub_bp)
app.register_blueprint(pages_bp)
app.register_blueprint(users_bp)
app.register_blueprint(system_bp)
app.register_blueprint(settings_bp)
# The Pub/Sub webhook is called by Google, not a browser -- it authenticates
# via a shared verification token, not a session/CSRF token, so it must be
# exempt from CSRF (it would otherwise 400 on every push).
csrf.exempt(pubsub_bp)

RETENTION_HOURS = 24  # FR-DB-05 / NFR-Security: don't keep raw bodies indefinitely


# ---------------------------------------------------------------------------
# Security headers (TLS itself is a deployment/reverse-proxy concern -- see
# README -- but these are real, applied on every response)
# ---------------------------------------------------------------------------
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "  # site/*.html has inline <style> blocks, no inline scripts
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    # HSTS only makes sense once the app is actually served over HTTPS
    # (true in production behind Render's TLS termination); emitting it over
    # plain-HTTP local dev would just be a lie the browser can't act on.
    if IS_PRODUCTION:
        resp.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains"
        )
    return resp


# ---------------------------------------------------------------------------
# Branded error pages (frontend revamp). Browser requests get a styled,
# self-contained error.html; API requests (path under /api/) keep the JSON
# contract the front-end scripts expect. Never exposes stack traces/secrets.
# ---------------------------------------------------------------------------
_ERROR_META = {
    400: (
        "Bad request",
        "The request couldn't be processed. If you were "
        "submitting a form, its security token may have expired — reload the "
        "page and try again.",
        False,
    ),
    403: (
        "Access denied",
        "You don't have permission to view this page. If "
        "you're an administrator, sign in with an administrator account.",
        True,
    ),
    404: (
        "Page not found",
        "The page you're looking for doesn't exist or may have moved.",
        False,
    ),
    429: (
        "Too many requests",
        "You've made too many requests in a short time. "
        "Please wait a moment and try again.",
        False,
    ),
    500: (
        "Something went wrong",
        "An unexpected error occurred on our side. "
        "The issue has been logged and we're looking into it.",
        False,
    ),
    503: (
        "Service unavailable",
        "Sentinel is temporarily unavailable. Please try again shortly.",
        False,
    ),
}


def _render_error(code):
    title, message, show_signin = _ERROR_META.get(code, _ERROR_META[500])
    if request.path.startswith("/api/"):
        return jsonify({"error": title}), code
    return render_template(
        "error.html",
        code=code,
        title=title,
        message=message,
        show_signin=show_signin,
    ), code


@app.errorhandler(400)
def err_400(e):
    return _render_error(400)


@app.errorhandler(403)
def err_403(e):
    return _render_error(403)


@app.errorhandler(404)
def err_404(e):
    return _render_error(404)


@app.errorhandler(429)
def err_429(e):
    return _render_error(429)


@app.errorhandler(500)
def err_500(e):
    return _render_error(500)


@app.errorhandler(503)
def err_503(e):
    return _render_error(503)


# ---------------------------------------------------------------------------
# Front-end: HTML pages are Jinja2 templates (backend/templates/) sharing
# base_marketing.html/base_app.html/base_auth.html for nav/footer instead
# of each page hand-duplicating that markup (see the plan doc -- this
# became untenable once the site grew past ~4 pages). CSS/JS/images stay
# static files served from site/, unchanged. `active_page` just drives
# which nav link gets the .active class in the base templates.
# ---------------------------------------------------------------------------
TEMPLATE_PAGES = {
    "index.html": {"active_page": "home"},
    "login.html": {},
    "signup.html": {},
    "forgot-password.html": {},
    "reset-password.html": {},
    "scan.html": {"active_page": "scan"},
    "admin.html": {"active_page": "admin"},
    "mailboxes.html": {"active_page": "admin"},
    "detections.html": {"active_page": "admin"},
    "report.html": {"active_page": "scan"},
    "account.html": {"active_page": "account"},
    "features.html": {"active_page": "features"},
    "how-it-works.html": {"active_page": "how-it-works"},
    "pricing.html": {"active_page": "pricing"},
    "about.html": {"active_page": "about"},
    "contact.html": {"active_page": "contact"},
    "faq.html": {},
    "privacy.html": {},
    "terms.html": {},
    "integrations.html": {},
    "changelog.html": {},
    "security.html": {},
    "resources.html": {},
    "status.html": {},
}


# ---------------------------------------------------------------------------
# Health endpoints -- for container orchestrators and external uptime
# monitors, deliberately NOT the same as the old healthcheck target
# (/api/public/demo-scan), which runs a full ML classification just to
# confirm the process is alive. Unauthenticated and rate-limit-exempt
# since a monitor polling every few seconds shouldn't get throttled.
# ---------------------------------------------------------------------------
@app.get("/healthz")
@limiter.exempt
def healthz():
    """Liveness: the process is up and can answer HTTP. No dependency
    checks -- that's /readyz's job. A container orchestrator restarts the
    process if this stops responding, so it should never fail for a
    reason a restart wouldn't fix (e.g. a slow database)."""
    return jsonify({"ok": True}), 200


@app.get("/readyz")
@limiter.exempt
def readyz():
    """Readiness: can this instance actually serve traffic right now --
    reaches Postgres and (if configured) Redis. Meant for load balancers
    deciding whether to route traffic here, not for restart decisions."""
    from sqlalchemy import text

    checks = {}
    try:
        db.session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"

    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        try:
            import redis as redis_lib

            redis_lib.from_url(redis_url, socket_connect_timeout=2).ping()
            checks["redis"] = "ok"
        except Exception as e:
            checks["redis"] = f"error: {e}"
    else:
        checks["redis"] = "not configured"

    healthy = all(v in ("ok", "not configured") for v in checks.values())
    return jsonify({"ok": healthy, "checks": checks}), (200 if healthy else 503)


@app.get("/api/csrf-token")
@limiter.exempt
def csrf_token():
    """Fetched by site/js/api.js before every state-changing request and
    sent back as the X-CSRFToken header. Unauthenticated on purpose --
    forms reachable before login (register, forgot-password) need a token
    too, and issuing one reveals nothing an attacker couldn't already get
    by loading the page themselves."""
    return jsonify({"csrf_token": generate_csrf()})


@app.route("/")
def root():
    return render_template("public/home.html", active_page="home")


@app.route("/<path:filename>")
def static_files(filename):
    if filename.startswith("api/"):
        return jsonify({"error": "not found"}), 404
    if filename in TEMPLATE_PAGES:
        return render_template(filename, **TEMPLATE_PAGES[filename])
    full = os.path.join(STATIC_DIR, filename)
    if os.path.isfile(full):
        return send_from_directory(STATIC_DIR, filename)
    return _render_error(404)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def new_scan_id():
    return "SCN-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def status_for(label):
    """Mailbox/queue disposition for a classification label.
    Phishing (High risk) -> quarantine. Needs Review (Medium risk) ->
    flag for analyst review, but never silently quarantine or drop it.
    Legitimate -> no action."""
    if label == "Phishing":
        return "Quarantined"
    if label == "Needs Review":
        return "Flagged"
    return "Delivered"


def purge_old_bodies():
    """FR-DB-05: minimise/anonymise sensitive content in storage. Real
    background job (not just a claim in the docs) that redacts email
    bodies once they pass the retention window, keeping only the
    classification metadata needed for auditing/reporting."""
    with app.app_context():
        cutoff = datetime.now(timezone.utc) - timedelta(hours=RETENTION_HOURS)
        cutoff_naive = cutoff.replace(tzinfo=None)
        old = Scan.query.filter(
            Scan.scan_timestamp < cutoff_naive, Scan.body_purged.is_(False)
        ).all()
        for s in old:
            s.body = None
            s.body_purged = True
        if old:
            db.session.commit()
            log_action(
                "system",
                "privacy_purge",
                details=f"Purged {len(old)} scan bodies older than {RETENTION_HOURS}h",
            )


## purge_loop / mailbox_poll_loop (in-process threading.Thread daemons) have
## been replaced by Celery Beat + worker jobs -- see celery_app.py and
## tasks.py. Running them as in-process threads meant every additional web
## replica would re-poll the same mailbox and re-run the same purge sweep;
## Celery Beat guarantees exactly one scheduler enqueues each job regardless
## of how many web/worker instances are running.


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
    result = infer.classify(
        DEMO_SAMPLE["subject"], DEMO_SAMPLE["body"], DEMO_SAMPLE["sender"]
    )
    result["subject"] = DEMO_SAMPLE["subject"]
    result["body"] = DEMO_SAMPLE["body"]
    result["from"] = DEMO_SAMPLE["sender"]
    return jsonify(result)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = verify_login(username, password)
    if not user:
        log_action(username or "unknown", "login_failed")
        return jsonify({"error": "Invalid username or password"}), 401
    # Self-registered accounts (have an email) must verify it first; seeded
    # demo accounts (no email) are never subject to this gate. Checked
    # here rather than inside verify_login() so this can return a message
    # distinct from "wrong password" -- see auth.py's verify_login docstring.
    if user.email and not user.email_verified:
        log_action(username, "login_blocked_unverified")
        return jsonify(
            {
                "error": "Please verify your email before logging in. Check your inbox for the verification link."
            }
        ), 403
    # Suspended accounts (Users & Roles console) must not be able to
    # authenticate at all -- checked after credentials so this never leaks
    # account existence to an attacker with the wrong password.
    if not user.is_active:
        log_action(username, "login_blocked_suspended")
        return jsonify(
            {"error": "This account has been suspended. Contact an administrator."}
        ), 403
    session["username"] = user.username
    session["role"] = user.role
    user.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    log_action(user.username, "login_success")
    return jsonify(user.to_public())


@app.post("/api/auth/register")
@limiter.limit("5 per hour")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    # Role is never read from the request body -- self-serve registration
    # can only ever create a "user" account (see auth.py/create_user's
    # default), preserving the Phase 1 decision that role is server-side
    # only, never client-chosen.
    if len(username) < 3 or len(username) > 80:
        return jsonify({"error": "Username must be 3-80 characters"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"error": "A valid email address is required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "That username is already taken"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "That email is already registered"}), 409

    user = create_user(username, password, role="user", email=email)
    token = generate_token()
    user.verification_token = token
    user.verification_token_expires = datetime.now(timezone.utc).replace(
        tzinfo=None
    ) + timedelta(hours=24)
    db.session.commit()

    verify_link = f"{public_base_url()}/verify-email/{token}"
    send_email(
        email,
        "Verify your Sentinel AI account",
        f"<p>Welcome to Sentinel AI. Click below to verify your account "
        f'(link expires in 24 hours):</p><p><a href="{html.escape(verify_link)}">{html.escape(verify_link)}</a></p>',
    )
    log_action(username, "register", details=email)
    return jsonify(
        {
            "ok": True,
            "message": "Account created. Check your email to verify your account before logging in.",
        }
    ), 201


@app.get("/verify-email/<token>")
def verify_email(token):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user = User.query.filter_by(verification_token=token).first()
    if (
        not user
        or not user.verification_token_expires
        or user.verification_token_expires < now
    ):
        return redirect("/login.html?verify_error=1")
    user.email_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    db.session.commit()
    log_action(user.username, "email_verified")
    return redirect("/login.html?verified=1")


@app.post("/api/auth/forgot-password")
@limiter.limit("5 per hour")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    # Always the same response regardless of whether the email exists --
    # a different response would let an attacker enumerate registered
    # emails one guess at a time.
    generic_response = jsonify(
        {
            "ok": True,
            "message": "If that email is registered, a reset link has been sent.",
        }
    )

    user = User.query.filter_by(email=email).first() if email else None
    if user:
        token = generate_token()
        user.reset_token = token
        user.reset_token_expires = datetime.now(timezone.utc).replace(
            tzinfo=None
        ) + timedelta(hours=1)
        db.session.commit()
        reset_link = f"{public_base_url()}/reset-password.html?token={token}"
        send_email(
            email,
            "Reset your Sentinel AI password",
            f"<p>Click below to reset your password (link expires in 1 hour):</p>"
            f'<p><a href="{html.escape(reset_link)}">{html.escape(reset_link)}</a></p>'
            f"<p>If you didn't request this, you can ignore this email.</p>",
        )
        log_action(user.username, "password_reset_requested")
    return generic_response


@app.post("/api/auth/reset-password")
@limiter.limit("10 per hour")
def reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token") or ""
    new_password = data.get("password") or ""

    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user = User.query.filter_by(reset_token=token).first() if token else None
    if not user or not user.reset_token_expires or user.reset_token_expires < now:
        return jsonify({"error": "This reset link is invalid or has expired"}), 400

    user.password_hash = generate_password_hash(new_password)
    user.reset_token = None
    user.reset_token_expires = None
    db.session.commit()
    log_action(user.username, "password_reset")
    return jsonify({"ok": True})


@app.post("/api/contact")
@limiter.limit("5 per hour")
def contact():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    subject = (data.get("subject") or "").strip() or "New contact form submission"
    message = (data.get("message") or "").strip()

    if not name or not EMAIL_RE.match(email) or not message:
        return jsonify(
            {"error": "Name, a valid email, and a message are required"}
        ), 400
    if len(message) > 5000:
        return jsonify({"error": "Message too long (max 5000 characters)"}), 400

    recipient = os.environ.get("CONTACT_RECIPIENT_EMAIL")
    sent = False
    if recipient:
        sent = send_email(
            recipient,
            f"[Sentinel Contact] {subject}",
            f"<p><b>From:</b> {html.escape(name)} ({html.escape(email)})</p><p>{html.escape(message)}</p>",
        )
    # Written to the audit log regardless of email outcome, so a
    # submission is never silently lost even if MAIL_* isn't configured or
    # a send fails -- see the note in the plan about the contact form not
    # depending solely on email delivery.
    note = (
        "" if sent else " (not emailed -- CONTACT_RECIPIENT_EMAIL unset or send failed)"
    )
    log_action(
        "anonymous",
        "contact_form_submitted",
        details=f"{name} <{email}>: {subject}{note}",
    )
    return jsonify(
        {
            "ok": True,
            "message": "Thanks for reaching out -- we'll get back to you soon.",
        }
    )


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
    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        return jsonify({"error": "not authenticated"}), 401
    return jsonify(user.to_public())


@app.post("/api/auth/change-password")
@login_required
@limiter.limit("10 per hour")
def change_password():
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""

    user = User.query.filter_by(username=session["username"]).first()
    if not user or not verify_login(user.username, current_password):
        return jsonify({"error": "Current password is incorrect"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    log_action(user.username, "password_changed")
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Scanning (FR-SE-01..12, FR-FE-01..08)
# ---------------------------------------------------------------------------
@app.post("/api/scan")
@login_required
@limiter.limit("30 per minute")
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
    status = status_for(result["label"])

    scan = Scan(
        scan_id=new_scan_id(),
        sender=sender or "(unknown sender)",
        subject=subject or "(no subject)",
        body=body,
        classification=result["label"],
        confidence_score=result["phishing_probability"],
        prediction_confidence=result["prediction_confidence"],
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
    log_action(
        current_actor(),
        "scan",
        target=scan.scan_id,
        details=f"{result['label']} ({result['score']}/100)",
    )
    return jsonify(scan.to_dict())


@app.get("/api/history")
@login_required
def history():
    status_filter = request.args.get("status")
    classification_filter = request.args.get("classification")
    released_filter = request.args.get("released")
    limit = min(int(request.args.get("limit", 100)), 500)

    # Ownership is enforced server-side, not opt-in: a non-admin only ever
    # sees their own scans, regardless of what the client sends (there used
    # to be a `mine=true` query param that only filtered when explicitly
    # requested -- that made ownership the caller's choice instead of the
    # server's, so any logged-in user could see every other user's scans
    # just by omitting it). Admins still see everything. Every filter
    # below is applied on top of that ownership scoping, not instead of
    # it, so combining filters can never widen access.
    q = Scan.query
    if session.get("role") != "admin":
        q = q.filter(Scan.created_by == session["username"])
    if status_filter and status_filter != "All":
        q = q.filter(Scan.status == status_filter)
    if classification_filter and classification_filter != "All":
        q = q.filter(Scan.classification == classification_filter)
    if released_filter and released_filter.lower() == "true":
        # "Released" isn't a status of its own (a release just returns a
        # scan to status=Delivered) -- this is the one signal unique to
        # that specific admin action, set in admin_action()'s "release"
        # branch below, so it's the only reliable way to distinguish
        # "delivered because it was never risky" from "delivered because
        # an admin released it after a false-positive quarantine/flag."
        q = q.filter(Scan.notes.like("Released by admin%"))
    scans = q.order_by(Scan.scan_timestamp.desc()).limit(limit).all()
    return jsonify([s.to_dict() for s in scans])


@app.get("/api/scan/<scan_id>")
@login_required
def get_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    if session.get("role") != "admin" and scan.created_by != session["username"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(scan.to_dict())


@app.get("/api/stats")
@login_required
def stats():
    is_admin = session.get("role") == "admin"
    q = (
        Scan.query
        if is_admin
        else Scan.query.filter(Scan.created_by == session["username"])
    )
    scans = q.all()
    total = len(scans)
    phishing = sum(1 for s in scans if s.classification == "Phishing")
    needs_review = sum(1 for s in scans if s.classification == "Needs Review")
    legitimate = total - phishing - needs_review
    quarantined = sum(1 for s in scans if s.status == "Quarantined")
    flagged = sum(1 for s in scans if s.status == "Flagged")

    # Two distinct numbers, not one ambiguous "avg_confidence": phishing
    # probability (raw model output) and prediction confidence (how sure
    # the model is of whichever label it picked -- see
    # Scan.effective_prediction_confidence(), which also covers rows
    # created before the prediction_confidence column existed).
    probabilities = [
        s.confidence_score for s in scans if s.confidence_score is not None
    ]
    confidences = [
        c for c in (s.effective_prediction_confidence() for s in scans) if c is not None
    ]
    avg_phishing_probability = (
        (sum(probabilities) / len(probabilities)) if probabilities else 0
    )
    avg_prediction_confidence = (
        (sum(confidences) / len(confidences)) if confidences else 0
    )

    return jsonify(
        {
            "total": total,
            "phishing": phishing,
            "needs_review": needs_review,
            "legitimate": legitimate,
            "quarantined": quarantined,
            "flagged": flagged,
            # Scans still awaiting an admin decision (quarantined or
            # flagged) -- not yet released or confirmed. Drives the admin
            # console's "items awaiting review" count.
            "pending_review": quarantined + flagged,
            "avg_phishing_probability": avg_phishing_probability,
            "avg_prediction_confidence": avg_prediction_confidence,
            "scope": "all_users" if is_admin else "own_scans",
        }
    )


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
        return jsonify(
            {"error": "corrected_label must be 'Phishing' or 'Legitimate'"}
        ), 400

    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404
    if session.get("role") != "admin" and scan.created_by != session["username"]:
        return jsonify({"error": "forbidden"}), 403

    fb = Feedback(
        scan_id=scan_id,
        original_label=scan.classification,
        corrected_label=corrected_label,
        submitted_by=current_actor(),
    )
    db.session.add(fb)
    scan.user_feedback = corrected_label
    scan.notes = f"User corrected to: {corrected_label}"
    db.session.commit()
    log_action(
        current_actor(),
        "feedback_submitted",
        target=scan_id,
        details=f"{scan.classification} -> {corrected_label}",
    )
    return jsonify(scan.to_dict())


@app.post("/api/admin/action")
@admin_required
def admin_action():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    action = data.get("action")  # release | confirm | escalate
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404

    if action == "release":
        scan.status = "Delivered"
        scan.notes = "Released by admin — marked false positive"
        fb = Feedback(
            scan_id=scan_id,
            original_label=scan.classification,
            corrected_label="Legitimate",
            submitted_by=current_actor(),
        )
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
        fb = Feedback(
            scan_id=scan_id,
            original_label=scan.classification,
            corrected_label="Phishing",
            submitted_by=current_actor(),
        )
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
    return jsonify(
        {
            "current": current,
            "versions": [v.to_dict() for v in versions],
            "pending_feedback_count": pending_feedback,
        }
    )


@app.post("/api/admin/retrain")
@admin_required
@limiter.limit("3 per hour")
def retrain():
    """
    Enqueues retraining on the Celery worker instead of running it (~1
    minute of CPU-bound scikit-learn training) on this request thread.
    Poll GET /api/admin/retrain/<job_id> with the returned id for status.
    """
    from tasks import retrain_task

    try:
        job = retrain_task.delay(current_actor())
    except Exception as e:
        return jsonify(
            {"error": f"Could not reach the job queue (Redis/Celery): {e}"}
        ), 503
    return jsonify({"job_id": job.id, "status": "queued"}), 202


@app.get("/api/admin/retrain/<job_id>")
@admin_required
def retrain_status(job_id):
    from celery.result import AsyncResult
    from celery_app import celery_app

    try:
        result = AsyncResult(job_id, app=celery_app)
        state = result.state
    except Exception as e:
        return jsonify(
            {"error": f"Could not reach the job queue (Redis/Celery): {e}"}
        ), 503

    if state == "PENDING":
        return jsonify({"job_id": job_id, "status": "pending"})
    if state == "STARTED":
        return jsonify({"job_id": job_id, "status": "running"})
    if state == "SUCCESS":
        payload = result.result
        return jsonify({"job_id": job_id, "status": "done", **payload})
    if state == "FAILURE":
        return jsonify(
            {"job_id": job_id, "status": "failed", "error": str(result.info)}
        ), 500
    return jsonify({"job_id": job_id, "status": state.lower()})


@app.post("/api/admin/model-version/<version>/promote")
@admin_required
@limiter.limit("20 per hour")
def promote_model_version(version):
    """
    The only route that changes which model version serves live traffic.
    Works the same whether `version` is a freshly trained candidate (the
    normal case) or an older, previously-live one -- promoting an older
    version IS the rollback mechanism, there's no separate rollback
    endpoint.
    """
    mv = db.session.get(ModelVersion, version)
    if not mv:
        return jsonify({"error": f"No such model version: {version}"}), 404

    try:
        infer.promote(version)
    except Exception as e:
        return jsonify({"error": f"Could not promote {version}: {e}"}), 500

    ModelVersion.query.update({ModelVersion.is_current: False})
    mv.is_current = True
    db.session.commit()

    log_action(current_actor(), "promote_model_version", target=version)
    return jsonify({"ok": True, "version": version})


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
        return jsonify(
            {
                "configured": cfg is not None,
                "connected": False,
                "last_sync_at": None,
                "last_error": None,
                "last_new_messages": 0,
                "total_synced": 0,
                "host": cfg.host if cfg else None,
                "username": cfg.username if cfg else None,
                "inbox_folder": cfg.inbox_folder if cfg else None,
                "quarantine_folder": cfg.quarantine_folder if cfg else None,
            }
        )
    return jsonify(row.to_dict())


@app.post("/api/admin/mailbox-test")
@admin_required
def mailbox_test():
    cfg = MailboxConfig.from_env()
    if not cfg:
        return jsonify(
            {
                "ok": False,
                "error": "Mailbox not configured — set MAILBOX_HOST / "
                "MAILBOX_USERNAME / MAILBOX_PASSWORD in backend/.env "
                "(see backend/.env.example)",
            }
        ), 400
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
    if not ALLOW_DEMO_SEED:
        return jsonify(
            {"error": "Demo data reset is disabled in this environment"}
        ), 403
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
ALLOW_DEMO_SEED = (not IS_PRODUCTION) or os.environ.get(
    "SENTINEL_ALLOW_DEMO_SEED", "false"
).lower() == "true"


def ensure_seed_data():
    """
    Schema creation is no longer this function's job -- `alembic upgrade
    head` (run before the app starts; see migrations/, docker-compose.yml,
    and the Render deploy config) is the single schema authority now.
    This only handles data: the current model-version row, and (dev-only)
    demo accounts/scans.
    """
    from seed_db import seed_users, seed_demo_scans, seed_model_version_row

    seed_model_version_row()  # records the trained model's own metrics -- not demo data, always safe
    if ALLOW_DEMO_SEED:
        seed_users()
        if Scan.query.count() == 0:
            seed_demo_scans()
    elif User.query.count() == 0:
        logger.warning(
            "SENTINEL_ENV=production: skipped seeding demo accounts/scans. "
            "No users exist yet -- create one with: "
            "python create_admin.py <username> <password> [--role admin|user]"
        )


if __name__ == "__main__":
    # Local dev only -- production runs via wsgi.py + gunicorn (see
    # docker-compose.yml / Render config). Periodic purge and mailbox sync
    # now run as Celery Beat jobs (celery_app.py, tasks.py), not threads
    # started here; run `celery -A celery_app worker` and
    # `celery -A celery_app beat` alongside this for local dev if you need
    # those jobs to actually fire.
    with app.app_context():
        ensure_seed_data()
    app.run(host="0.0.0.0", port=5000, debug=False)
