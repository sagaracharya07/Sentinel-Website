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
            "username": self.username, "role": self.role,
            "email": self.email, "email_verified": self.email_verified,
        }


class Scan(db.Model):
    """One row per FR-DB-01: 'classification results for each analysed email'."""
    __tablename__ = "scans"
    scan_id = db.Column(db.String(20), primary_key=True)

    sender = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    body = db.Column(db.Text)                 # redacted after retention window (FR-DB-05)
    body_purged = db.Column(db.Boolean, default=False)

    classification = db.Column(db.String(20))       # 'Phishing' | 'Needs Review' | 'Legitimate'
    confidence_score = db.Column(db.Float)           # FR-DB-03 -- despite the name, this is actually the
                                                      # phishing probability (see phishing_probability below);
                                                      # kept under its original name for backward compatibility
                                                      # with existing rows/consumers rather than renamed in place.
    prediction_confidence = db.Column(db.Float)      # how sure the model is of *whichever* label it picked --
                                                      # max(phishing_probability, 1 - phishing_probability).
                                                      # Nullable: old rows predate this column (see to_dict()).
    score = db.Column(db.Integer)                    # 0-100 raw model score
    risk_level = db.Column(db.String(10))            # Low | Medium | High
    findings_json = db.Column(db.Text)               # explainability payload
    highlights_json = db.Column(db.Text)

    status = db.Column(db.String(20), default="Delivered")  # Delivered|Flagged|Quarantined
    user_feedback = db.Column(db.String(20))          # corrected label, if any
    notes = db.Column(db.Text, default="")

    scan_timestamp = db.Column(db.DateTime, default=utcnow)  # FR-DB-02
    model_version = db.Column(db.String(10))
    created_by = db.Column(db.String(80), default="system")

    # --- real mailbox integration ---
    source = db.Column(db.String(20), default="manual")   # 'manual' | 'mailbox'
    mailbox_uid = db.Column(db.String(50))                 # IMAP UID, unique within a folder (see partial index below)
    mailbox_message_id = db.Column(db.String(255))         # RFC Message-ID, stable across folders/moves
    mailbox_action = db.Column(db.String(20))              # 'none' | 'quarantined' | 'flagged'
    mailbox_action_error = db.Column(db.Text)              # set if the real mailbox move/flag failed

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
            "uq_scans_mailbox_uid", "mailbox_uid", unique=True,
            sqlite_where=db.text("source = 'mailbox' AND mailbox_uid IS NOT NULL"),
            postgresql_where=db.text("source = 'mailbox' AND mailbox_uid IS NOT NULL"),
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

    def to_dict(self):
        # Old rows (pre prediction_confidence column) don't have this
        # stored -- derive it from confidence_score (== phishing_probability)
        # the same way ml/infer.py does, rather than showing null.
        pred_confidence = self.prediction_confidence
        if pred_confidence is None and self.confidence_score is not None:
            pred_confidence = max(self.confidence_score, 1 - self.confidence_score)

        return {
            "scan_id": self.scan_id,
            "from": self.sender,
            "subject": self.subject,
            "body": "[content purged per data-minimisation policy]" if self.body_purged else self.body,
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
            "scan_timestamp": self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            "model_version": self.model_version,
            "source": self.source,
            "mailbox_action": self.mailbox_action,
            "mailbox_action_error": self.mailbox_action_error,
            "mailbox_message_id": self.mailbox_message_id,
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
            "accuracy": self.accuracy, "precision": self.precision, "recall": self.recall,
            "f1_score": self.f1_score,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "n_train": self.n_train, "n_test": self.n_test,
            "n_feedback_folded_in": self.n_feedback_folded_in,
            "notes": self.notes, "is_current": self.is_current,
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
            "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
            "last_error": self.last_error,
            "last_new_messages": self.last_new_messages,
            "total_synced": self.total_synced,
            "host": self.host,
            "username": self.username,
            "inbox_folder": self.inbox_folder,
            "quarantine_folder": self.quarantine_folder,
            "sync_in_progress": self.sync_in_progress,
        }


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
            "actor": self.actor, "action": self.action, "target": self.target,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
