"""
Database models for the Sentinel AI Phishing Detection Platform.

Maps directly onto the "Example Database Scheme" in the project report
(Section 2.3): scan_id, email_subject, classification, confidence_score,
scan_timestamp, risk_level, user_feedback, notes -- extended with the
extra columns a working system actually needs (sender, findings,
status, model_version, audit trail, feedback history, model versioning).
"""

import json
from datetime import datetime, timezone

import crypto
from extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # 'user' | 'admin'
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    # Administrator account suspension (Users & Roles console, Phase 16).
    # Suspended users fail login (see auth.py's verify_login) but keep their
    # row and history -- suspension is reversible, not a deletion.
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # Self-serve registration (nullable so the seeded admin/user demo
    # accounts, which have no email, are unaffected by the verification
    # gate in auth.py's verify_login()).
    email = db.Column(db.String(255), unique=True, nullable=True)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    verification_token = db.Column(db.String(64), nullable=True)
    verification_token_expires = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(64), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    def to_public(self):
        return {
            "username": self.username,
            "role": self.role,
            "email": self.email,
            "email_verified": self.email_verified,
            "is_active": self.is_active,
        }

    def to_admin_dict(self):
        """Admin-facing user list row (Users & Roles). Never includes
        password_hash or any token."""
        report_count = Scan.query.filter_by(created_by=self.username).count()
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "email": self.email,
            "email_verified": self.email_verified,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat()
            if self.last_login_at
            else None,
            "report_count": report_count,
        }


class Scan(db.Model):
    """One row per FR-DB-01: 'classification results for each analysed email'."""

    __tablename__ = "scans"
    scan_id = db.Column(db.String(20), primary_key=True)

    sender = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    body = db.Column(db.Text)  # redacted after retention window (FR-DB-05)
    body_purged = db.Column(db.Boolean, default=False)

    classification = db.Column(
        db.String(20)
    )  # 'Phishing' | 'Needs Review' | 'Legitimate'
    confidence_score = db.Column(
        db.Float
    )  # FR-DB-03 -- despite the name, this is actually the
    # phishing probability (see phishing_probability below);
    # kept under its original name for backward compatibility
    # with existing rows/consumers rather than renamed in place.
    prediction_confidence = db.Column(
        db.Float
    )  # how sure the model is of *whichever* label it picked --
    # max(phishing_probability, 1 - phishing_probability).
    # Nullable: old rows predate this column (see to_dict()).
    score = db.Column(db.Integer)  # 0-100 raw model score
    risk_level = db.Column(db.String(10))  # Low | Medium | High
    findings_json = db.Column(db.Text)  # explainability payload
    highlights_json = db.Column(db.Text)

    status = db.Column(
        db.String(20), default="Delivered"
    )  # Delivered|Flagged|Quarantined
    user_feedback = db.Column(db.String(20))  # corrected label, if any
    notes = db.Column(db.Text, default="")

    scan_timestamp = db.Column(db.DateTime, default=utcnow)  # FR-DB-02
    model_version = db.Column(db.String(10))
    created_by = db.Column(db.String(80), default="system")

    # --- real mailbox integration ---
    # source: 'manual' (Quick Analysis) | 'mailbox' (legacy IMAP) |
    #         'gmail' (connected Gmail mailbox) | 'upload' (.eml, added in CP4)
    source = db.Column(db.String(20), default="manual")
    mailbox_uid = db.Column(
        db.String(50)
    )  # IMAP UID, unique within a folder (see partial index below)
    mailbox_message_id = db.Column(
        db.String(255)
    )  # RFC Message-ID, stable across folders/moves
    # mailbox_action semantics differ by source: IMAP uses 'quarantined'/
    # 'flagged' (folder move / flag); Gmail uses 'quarantined'/'needs_review'/
    # 'processed'/'scan_failed'/'none' (label operations -- see
    # integrations/gmail/messages.py).
    mailbox_action = db.Column(
        db.String(20)
    )  # 'none' | 'quarantined' | 'flagged' | ...
    mailbox_action_error = db.Column(
        db.Text
    )  # set if the real mailbox move/flag failed

    # --- connected Gmail mailbox (source='gmail') ---
    # Plain indexed integer, not a DB-level ForeignKey, on purpose: it points
    # at gmail_connections.id but SQLite can't ADD a FK column without
    # rebuilding the whole table (which would jeopardise the partial unique
    # indexes above). Referential use is by explicit filter, same as the IMAP
    # side, which likewise doesn't FK into mailbox_status.
    gmail_connection_id = db.Column(db.Integer, index=True)
    gmail_message_id = db.Column(
        db.String(120)
    )  # Gmail's message id (stable per mailbox)
    gmail_thread_id = db.Column(db.String(120))
    gmail_history_id = db.Column(db.String(50))

    __table_args__ = (
        # Backstop against double-processing the same mailbox message --
        # the sync lock (MailboxStatus.sync_in_progress) is the primary
        # defense against concurrent syncs, but this is what actually
        # guarantees no duplicate Scan row can exist for one UID even if
        # that lock is ever bypassed (e.g. a stale-lock takeover after a
        # crash). Partial index because 'manual' scans have no mailbox_uid
        # and mustn't collide with each other on NULL.
        #
        # Known limitation for this single-mailbox prototype: the key is
        # UID alone, not (account, folder, UIDVALIDITY, UID) -- IMAP UIDs
        # are only guaranteed unique within one folder for one UIDVALIDITY
        # epoch. Fine as long as there's exactly one configured mailbox
        # account and its folder isn't recreated; documented in the README
        # as a known limitation rather than fully solved here.
        db.Index(
            "uq_scans_mailbox_uid",
            "mailbox_uid",
            unique=True,
            sqlite_where=db.text("source = 'mailbox' AND mailbox_uid IS NOT NULL"),
            postgresql_where=db.text("source = 'mailbox' AND mailbox_uid IS NOT NULL"),
        ),
        # Gmail dedup backstop: no duplicate Scan row for the same Gmail
        # message within one connection, even if the sync lock is ever
        # bypassed (mirrors the IMAP-UID index above). Keyed on
        # (gmail_connection_id, gmail_message_id) because Gmail message ids
        # are only unique within a single mailbox. Partial so non-Gmail rows
        # (NULL gmail_message_id) never collide.
        db.Index(
            "uq_scans_gmail_message",
            "gmail_connection_id",
            "gmail_message_id",
            unique=True,
            sqlite_where=db.text("source = 'gmail' AND gmail_message_id IS NOT NULL"),
            postgresql_where=db.text(
                "source = 'gmail' AND gmail_message_id IS NOT NULL"
            ),
        ),
    )

    def findings(self):
        try:
            return json.loads(self.findings_json or "[]")
        except (TypeError, ValueError):
            return []

    def highlights(self):
        try:
            return json.loads(self.highlights_json or "[]")
        except (TypeError, ValueError):
            return []

    def effective_prediction_confidence(self):
        """
        prediction_confidence if this row has it; otherwise derived from
        confidence_score (== phishing_probability) the same way
        ml/infer.py computes it for new scans: max(p, 1-p). Old rows
        (pre prediction_confidence column) don't have it stored, and
        confidence_score can itself be None for a handful of edge cases
        (e.g. a row created without a classification) -- in that case
        this returns None rather than a fabricated number. Shared by
        to_dict() and /api/stats so both use one definition, not two.
        """
        if self.prediction_confidence is not None:
            return self.prediction_confidence
        if self.confidence_score is not None:
            return max(self.confidence_score, 1 - self.confidence_score)
        return None

    def to_dict(self):
        pred_confidence = self.effective_prediction_confidence()

        return {
            "scan_id": self.scan_id,
            "from": self.sender,
            "subject": self.subject,
            "body": "[content purged per data-minimisation policy]"
            if self.body_purged
            else self.body,
            "body_purged": self.body_purged,
            "classification": self.classification,
            "confidence_score": self.confidence_score,  # deprecated: this is actually phishing_probability
            "phishing_probability": self.confidence_score,
            "prediction_confidence": pred_confidence,
            "score": self.score,
            "risk_level": self.risk_level,
            "findings": self.findings(),
            "highlights": self.highlights(),
            "status": self.status,
            "user_feedback": self.user_feedback,
            "notes": self.notes,
            "scan_timestamp": self.scan_timestamp.isoformat()
            if self.scan_timestamp
            else None,
            "model_version": self.model_version,
            "source": self.source,
            "mailbox_action": self.mailbox_action,
            "mailbox_action_error": self.mailbox_action_error,
            "mailbox_message_id": self.mailbox_message_id,
            "gmail_connection_id": self.gmail_connection_id,
            "gmail_message_id": self.gmail_message_id,
            "gmail_thread_id": self.gmail_thread_id,
        }


class Feedback(db.Model):
    """FR-DB-07: user feedback and corrections to support model retraining."""

    __tablename__ = "feedback"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.String(20), db.ForeignKey("scans.scan_id"), nullable=False)
    original_label = db.Column(db.String(20))
    corrected_label = db.Column(db.String(20))
    submitted_by = db.Column(db.String(80))
    submitted_at = db.Column(db.DateTime, default=utcnow)
    used_in_retrain = db.Column(db.Boolean, default=False)


class ModelVersion(db.Model):
    """Tracks every trained model so retraining is auditable (UC-07)."""

    __tablename__ = "model_versions"
    version = db.Column(db.String(10), primary_key=True)
    trained_at = db.Column(db.DateTime, default=utcnow)
    accuracy = db.Column(db.Float)
    precision = db.Column(db.Float)
    recall = db.Column(db.Float)
    f1_score = db.Column(db.Float)
    false_positive_rate = db.Column(db.Float)
    false_negative_rate = db.Column(db.Float)
    n_train = db.Column(db.Integer)
    n_test = db.Column(db.Integer)
    n_feedback_folded_in = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text)
    is_current = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "version": self.version,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "n_train": self.n_train,
            "n_test": self.n_test,
            "n_feedback_folded_in": self.n_feedback_folded_in,
            "notes": self.notes,
            "is_current": self.is_current,
        }


class MailboxStatus(db.Model):
    """
    Singleton-ish row (id=1) tracking the state of the live IMAP
    connection: whether it's configured/reachable, when it last synced,
    how many messages it pulled, and the last error (if any) -- this is
    what the admin console's "Mailbox" panel reads to show real
    connection health instead of a fake "connected" label.
    """

    __tablename__ = "mailbox_status"
    id = db.Column(db.Integer, primary_key=True)
    configured = db.Column(db.Boolean, default=False)
    connected = db.Column(db.Boolean, default=False)
    last_sync_at = db.Column(db.DateTime)
    last_error = db.Column(db.Text)
    last_new_messages = db.Column(db.Integer, default=0)
    total_synced = db.Column(db.Integer, default=0)
    host = db.Column(db.String(255))
    username = db.Column(db.String(255))
    inbox_folder = db.Column(db.String(120))
    quarantine_folder = db.Column(db.String(120))

    # DB-backed sync lock: prevents the Celery-Beat-scheduled sync and a
    # manual admin "Sync now" click from running concurrently against the
    # same mailbox (see mailbox/sync.py's _try_acquire_sync_lock()).
    # sync_lock_acquired_at lets a stale lock (the process holding it died
    # without releasing) be taken over after a timeout instead of
    # deadlocking sync forever.
    sync_in_progress = db.Column(db.Boolean, default=False)
    sync_lock_acquired_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "configured": self.configured,
            "connected": self.connected,
            "last_sync_at": self.last_sync_at.isoformat()
            if self.last_sync_at
            else None,
            "last_error": self.last_error,
            "last_new_messages": self.last_new_messages,
            "total_synced": self.total_synced,
            "host": self.host,
            "username": self.username,
            "inbox_folder": self.inbox_folder,
            "quarantine_folder": self.quarantine_folder,
            "sync_in_progress": self.sync_in_progress,
        }


# Connection lifecycle states for a Gmail mailbox. Kept as module-level
# constants so routes/tasks/tests all reference one spelling.
GMAIL_STATUS_CONNECTED = "connected"
GMAIL_STATUS_PAUSED = "paused"
GMAIL_STATUS_DISCONNECTED = "disconnected"
GMAIL_STATUS_ERROR = "error"
GMAIL_STATUS_REVOKED = "revoked"


class GmailConnection(db.Model):
    """
    One connected Gmail mailbox, authorised via Google OAuth. Replaces the
    env-var IMAP app-password model for the primary integration: the
    administrator connects a mailbox from the website and Sentinel stores an
    *encrypted* refresh token (never a password) to keep access.

    Scope note: this prototype supports one active Gmail connection per
    deployment (see active()). Rows for previously-connected mailboxes are
    kept with status='disconnected' for audit history rather than deleted.
    Tokens are stored encrypted (see crypto.py) and are NEVER exposed via
    to_dict()/to_public(), templates, APIs, or logs.
    """

    __tablename__ = "gmail_connections"

    id = db.Column(db.Integer, primary_key=True)
    # The administrator who connected this mailbox (mailbox management is
    # admin-only -- see routes/gmail.py).
    owner_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True, index=True
    )
    provider = db.Column(db.String(20), nullable=False, default="gmail")
    mailbox_email = db.Column(db.String(255), index=True)
    provider_account_id = db.Column(db.String(255))  # Google 'sub' -- stable id

    # Encrypted at rest (crypto.encrypt). The access token is short-lived
    # and mostly re-derived from the refresh token, but caching it avoids a
    # refresh round-trip on every call within its ~1h validity window.
    encrypted_refresh_token = db.Column(db.Text)
    encrypted_access_token = db.Column(db.Text)
    token_expiry = db.Column(db.DateTime)
    granted_scopes = db.Column(db.Text)  # space-separated scope list

    connection_status = db.Column(
        db.String(20), nullable=False, default=GMAIL_STATUS_CONNECTED, index=True
    )
    protection_enabled = db.Column(db.Boolean, nullable=False, default=True)
    monitoring_mode = db.Column(db.String(20), default="polling")  # polling|push

    last_successful_sync_at = db.Column(db.DateTime)
    last_attempted_sync_at = db.Column(db.DateTime)
    last_history_id = db.Column(db.String(50))
    last_watch_expiration = db.Column(db.DateTime)
    last_error_code = db.Column(db.String(60))
    last_error_message = db.Column(db.Text)

    # Gmail label IDs discovered/created for this mailbox (Phase 3 / CP2).
    processed_label_id = db.Column(db.String(120))
    needs_review_label_id = db.Column(db.String(120))
    quarantine_label_id = db.Column(db.String(120))
    scan_failed_label_id = db.Column(db.String(120))

    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    disconnected_at = db.Column(db.DateTime)

    # DB-backed sync lock (same compare-and-set pattern as MailboxStatus for
    # IMAP): stops the Celery-Beat poll and a manual "Scan now" from running
    # concurrently against the same mailbox. A stale lock (holder crashed) is
    # taken over after a timeout instead of deadlocking forever.
    sync_in_progress = db.Column(db.Boolean, nullable=False, default=False)
    sync_lock_acquired_at = db.Column(db.DateTime)

    @classmethod
    def active(cls):
        """The single non-disconnected connection, if any. There is at most
        one at a time by construction (the connect flow disconnects any
        prior active mailbox before storing a new one)."""
        return cls.query.filter(
            cls.connection_status != GMAIL_STATUS_DISCONNECTED
        ).first()

    # --- token accessors (encryption boundary lives here, not in routes) ---
    def set_refresh_token(self, token: str):
        self.encrypted_refresh_token = crypto.encrypt(token) if token else None

    def get_refresh_token(self):
        if not self.encrypted_refresh_token:
            return None
        return crypto.decrypt(self.encrypted_refresh_token)

    def set_access_token(self, token: str):
        self.encrypted_access_token = crypto.encrypt(token) if token else None

    def get_access_token(self):
        if not self.encrypted_access_token:
            return None
        return crypto.decrypt(self.encrypted_access_token)

    def mark_disconnected(self):
        """Clear credentials and flag the row disconnected. Encrypted tokens
        are wiped so a disconnect genuinely revokes stored access rather
        than just hiding it behind a status flag."""
        self.connection_status = GMAIL_STATUS_DISCONNECTED
        self.protection_enabled = False
        self.encrypted_refresh_token = None
        self.encrypted_access_token = None
        self.token_expiry = None
        self.disconnected_at = utcnow()

    def to_dict(self):
        """Admin-facing status. Deliberately omits every token field and the
        provider_account_id -- nothing here is a secret an admin console
        shouldn't show, and nothing here is a credential."""
        return {
            "id": self.id,
            "provider": self.provider,
            "mailbox_email": self.mailbox_email,
            "connection_status": self.connection_status,
            "protection_enabled": self.protection_enabled,
            "monitoring_mode": self.monitoring_mode,
            "granted_scopes": (self.granted_scopes or "").split()
            if self.granted_scopes
            else [],
            "last_successful_sync_at": self.last_successful_sync_at.isoformat()
            if self.last_successful_sync_at
            else None,
            "last_attempted_sync_at": self.last_attempted_sync_at.isoformat()
            if self.last_attempted_sync_at
            else None,
            "last_error_code": self.last_error_code,
            "last_error_message": self.last_error_message,
            "labels_ready": all(
                [
                    self.processed_label_id,
                    self.needs_review_label_id,
                    self.quarantine_label_id,
                    self.scan_failed_label_id,
                ]
            ),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "disconnected_at": self.disconnected_at.isoformat()
            if self.disconnected_at
            else None,
        }


class EmailReport(db.Model):
    """
    An employee-submitted `.eml` report (Phase 11). The uploaded file is
    analysed through the same pipeline as Gmail mail -- the result is stored
    as a Scan row (source='upload', linked via scan_id) -- and this row adds
    the user-report lifecycle on top: who submitted it, its review status,
    and the administrator's final verdict.

    Ownership is enforced everywhere: a normal user sees only their own
    reports; only administrators review them.
    """

    __tablename__ = "email_reports"
    id = db.Column(db.Integer, primary_key=True)
    reporter_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    reporter_username = db.Column(db.String(80))  # denormalised for display
    filename = db.Column(db.String(255))  # sanitised original filename
    stored_path = db.Column(db.String(500))  # on-disk path, outside static
    scan_id = db.Column(db.String(20), db.ForeignKey("scans.scan_id"))
    status = db.Column(
        db.String(20), nullable=False, default="pending", index=True
    )  # pending | reviewed
    admin_verdict = db.Column(db.String(20))  # Phishing | Legitimate | None
    reviewed_by = db.Column(db.String(80))
    reviewed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow)

    def to_dict(self, scan=None):
        d = {
            "id": self.id,
            "reporter_username": self.reporter_username,
            "filename": self.filename,
            "scan_id": self.scan_id,
            "status": self.status,
            "admin_verdict": self.admin_verdict,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if scan is not None:
            d["scan"] = scan.to_dict()
        return d


class AuditLog(db.Model):
    """FR-DB-04 / FR-SE-09: audit logs for monitoring and troubleshooting."""

    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    actor = db.Column(db.String(80))
    action = db.Column(db.String(80))
    target = db.Column(db.String(80))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=utcnow)

    def to_dict(self):
        return {
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


# Detection-policy thresholds shipped as code constants in ml/infer.py's
# decide() until Phase 16 -- not configurable without a redeploy. This is the
# one genuinely-required Settings write path from the frontend-revamp
# direction (Checkpoint 0's approved small-backend-additions list): admins
# need to see and adjust the Needs-Review / Phishing cut points without
# retraining or redeploying the model.
DEFAULT_NEEDS_REVIEW_THRESHOLD = 0.50
DEFAULT_PHISHING_THRESHOLD = 0.75


class AppSettings(db.Model):
    """
    Singleton row (id=1) for admin-configurable, non-secret application
    settings. Deliberately narrow in scope: only Detection Policy thresholds
    are writable in this revision. Every other "Settings" page in the
    revamped console reads real configuration (env vars, feature flags) and
    labels it Deployment Managed / Read Only rather than writing here --
    see docs/SETTINGS.md.
    """

    __tablename__ = "app_settings"
    id = db.Column(db.Integer, primary_key=True)
    needs_review_threshold = db.Column(
        db.Float, nullable=False, default=DEFAULT_NEEDS_REVIEW_THRESHOLD
    )
    phishing_threshold = db.Column(
        db.Float, nullable=False, default=DEFAULT_PHISHING_THRESHOLD
    )
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)
    updated_by = db.Column(db.String(80))

    @classmethod
    def current(cls):
        """The single settings row, creating it with defaults on first use
        (mirrors MailboxStatus's id=1 singleton pattern)."""
        row = db.session.get(cls, 1)
        if row is None:
            row = cls(
                id=1,
                needs_review_threshold=DEFAULT_NEEDS_REVIEW_THRESHOLD,
                phishing_threshold=DEFAULT_PHISHING_THRESHOLD,
            )
            db.session.add(row)
            db.session.commit()
        return row

    def to_dict(self):
        return {
            "needs_review_threshold": self.needs_review_threshold,
            "phishing_threshold": self.phishing_threshold,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "updated_by": self.updated_by,
        }
