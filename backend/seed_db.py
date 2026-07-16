"""
Seeds the database with:
  - two demo accounts (admin/admin123, user/user123) -- credentials are
    shown on the login screen for this academic demo build, clearly
    labelled as such
  - the current trained model's metrics as ModelVersion row 1
  - a handful of realistic sample scans spread over the last few days,
    matching what the original localStorage demo used to seed, so the
    admin dashboard and scan history aren't empty on first run

Called automatically from app.py on first startup (ensure_seed_data);
can also be run standalone: `python3 seed_db.py`.
"""
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError

from extensions import db
from models import User, Scan, ModelVersion
from auth import create_user
from ml import infer


def seed_users():
    """
    Guarded by count() == 0 to skip the common case cheaply, but that
    check-then-act isn't atomic -- with multiple web replicas starting
    concurrently (see seed_startup.py's docstring for how this was found:
    two gunicorn workers racing on the same INSERT crashed the whole
    process), two replicas could both pass the check before either
    commits. Catching the resulting UniqueViolation and rolling back
    treats "someone else already seeded this" as success, not a crash.
    """
    if User.query.count() == 0:
        try:
            create_user("admin", "admin123", role="admin")
            create_user("user", "user123", role="user")
            print("Seeded demo accounts: admin/admin123 (admin), user/user123 (user)")
        except IntegrityError:
            db.session.rollback()


def seed_model_version_row():
    info = infer.current_info()
    version = info["version"]
    if ModelVersion.query.get(version):
        return
    m = info["metrics"]
    meta = info["meta"]
    ModelVersion.query.update({ModelVersion.is_current: False})
    db.session.add(ModelVersion(
        version=version, accuracy=m["accuracy"], precision=m["precision"],
        recall=m["recall"], f1_score=m["f1_score"],
        false_positive_rate=m["false_positive_rate"],
        false_negative_rate=m["false_negative_rate"],
        n_train=m["n_train"], n_test=m["n_test"],
        n_feedback_folded_in=meta.get("n_feedback_folded_in", 0),
        notes=meta.get("notes", ""), is_current=True,
    ))
    try:
        db.session.commit()
    except IntegrityError:
        # Another replica seeded this exact version row first -- fine,
        # that's the same outcome we were trying to reach.
        db.session.rollback()


SAMPLE_EMAILS = [
    dict(subject="Your account will be suspended — verify now",
         sender="PayPal Security <security@paypa1-support.com>",
         body="Dear Customer,\n\nWe detected unusual activity on your account. Verify your "
              "account immediately or it will be suspended within 24 hours.\n\nClick here to "
              "confirm your password and avoid interruption: http://bit.ly/verify-acct\n\n"
              "PayPal Security Team", offset_hours=4, created_by="user"),
    dict(subject="Invoice #4471 from A1 Ultimate Roofing",
         sender="billing@a1ultimateroofing.com.au",
         body="Hi team, attached is invoice #4471 for the Kurnell job completed last week. "
              "Let me know if you have any questions.\n\nThanks,\nSagar",
         offset_hours=11, created_by="user"),
    dict(subject="URGENT: Confirm your banking details",
         sender="Commonwealth Bank <alerts@cba-secure-login.net>",
         body="Dear valued customer, unauthorized login detected. Confirm your password and "
              "card verification number immediately to avoid account closure. "
              "http://103.22.4.19/cba/login", offset_hours=26, created_by="admin"),
    dict(subject="Team meeting notes — kickoff",
         sender="sagar.acharya@live.vu.edu.au",
         body="Hi all, following up again on scheduling our kickoff meeting this week. "
              "Let me know your availability.", offset_hours=34, created_by="user"),
    dict(subject="Re: Roofing materials quote",
         sender="sales@colorbondsuppliesau.com",
         body="Hi Sagar, please find attached the updated Colorbond pricing for the Riverwood "
              "job as discussed on the phone.", offset_hours=50, created_by="user"),
    dict(subject="Final Notice: Payment failed, reactivate your account",
         sender="Netflix <no-reply@netflix-billing-update.com>",
         body="Your payment has failed! Reactivate your account now to avoid interruption. "
              "Update your billing details here: http://tinyurl.com/nflx-update",
         offset_hours=63, created_by="admin"),
    dict(subject="Congratulations! You have won a prize",
         sender="promotions@lucky-draw-winners.info",
         body="Dear Winner, you have been selected to receive $500,000 in our international "
              "lottery draw. To claim your prize, reply with your full name, address and bank "
              "account number immediately. Act now, this offer expires in 24 hours!",
         offset_hours=70, created_by="user"),
    dict(subject="Lunch tomorrow?",
         sender="friend.colleague@gmail.com",
         body="Hey, are we still on for lunch tomorrow at 12? Let me know.",
         offset_hours=80, created_by="user"),
]


def seed_demo_scans():
    import random
    import string

    def new_id():
        return "SCN-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))

    now = datetime.now(timezone.utc)
    for item in SAMPLE_EMAILS:
        result = infer.classify(item["subject"], item["body"], item["sender"])
        ts = (now - timedelta(hours=item["offset_hours"])).replace(tzinfo=None)
        status = "Delivered"
        if result["label"] == "Phishing":
            status = "Quarantined" if result["risk_level"] == "High" else "Flagged"
        db.session.add(Scan(
            scan_id=new_id(), sender=item["sender"], subject=item["subject"],
            body=item["body"], classification=result["label"],
            confidence_score=result["confidence"], score=result["score"],
            risk_level=result["risk_level"], findings_json=json.dumps(result["findings"]),
            highlights_json=json.dumps(result["highlights"]), status=status,
            scan_timestamp=ts, model_version=result["model_version"],
            created_by=item["created_by"],
        ))
    db.session.commit()
    print(f"Seeded {len(SAMPLE_EMAILS)} demo scans")


if __name__ == "__main__":
    from app import app
    with app.app_context():
        db.create_all()
        seed_users()
        seed_model_version_row()
        seed_demo_scans()
