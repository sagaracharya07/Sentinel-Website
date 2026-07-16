"""
Celery tasks wrapping Sentinel's background jobs. Each task wraps existing
logic (purge_old_bodies in app.py, sync_mailbox in mailbox/sync.py, and the
retrain body that used to live directly in the POST /api/admin/retrain
route) essentially verbatim -- this module is a relocation from in-process
threads/request-thread work to a supervised job queue, not a behavior
rewrite. See celery_app.py for the Beat schedule that enqueues the periodic
jobs.
"""
from celery.utils.log import get_task_logger

from celery_app import celery_app

logger = get_task_logger(__name__)


def _app_context():
    from app import app
    return app.app_context()


@celery_app.task(name="tasks.purge_old_bodies_task")
def purge_old_bodies_task():
    with _app_context():
        from app import purge_old_bodies
        purge_old_bodies()


@celery_app.task(name="tasks.mailbox_sync_task")
def mailbox_sync_task():
    with _app_context():
        from mailbox.sync import sync_mailbox
        from auth import log_action
        result = sync_mailbox(log_action=log_action)
        if result.get("error"):
            logger.warning("mailbox_sync_task: %s", result["error"])
        return result


@celery_app.task(name="tasks.retrain_task", bind=True)
def retrain_task(self, actor: str):
    """
    Runs off the request thread so POST /api/admin/retrain can return
    immediately with a job id instead of blocking on ~1 minute of training
    (see app.py's retrain() route, which now just calls
    retrain_task.delay(...) and hands back self.request.id for polling via
    GET /api/admin/retrain/<job_id>).
    """
    with _app_context():
        import pandas as pd
        from extensions import db
        from models import Feedback, Scan, ModelVersion
        from ml import train as train_module
        from ml import infer
        from auth import log_action

        pending = Feedback.query.filter_by(used_in_retrain=False).all()
        rows = []
        for fb in pending:
            scan = Scan.query.get(fb.scan_id)
            if not scan or scan.body_purged or not scan.body:
                continue
            rows.append({
                "sender": scan.sender or "",
                "subject": scan.subject or "",
                "body": scan.body or "",
                "label": 1 if fb.corrected_label == "Phishing" else 0,
            })

        extra_df = pd.DataFrame(rows) if rows else None
        notes = f"Retrained with {len(rows)} confirmed feedback correction(s)"
        version, metrics, meta = train_module.train(extra_df=extra_df, notes=notes)

        ModelVersion.query.update({ModelVersion.is_current: False})
        mv = ModelVersion(
            version=version, accuracy=metrics["accuracy"], precision=metrics["precision"],
            recall=metrics["recall"], f1_score=metrics["f1_score"],
            false_positive_rate=metrics["false_positive_rate"],
            false_negative_rate=metrics["false_negative_rate"],
            n_train=metrics["n_train"], n_test=metrics["n_test"],
            n_feedback_folded_in=len(rows), notes=notes, is_current=True,
        )
        db.session.add(mv)
        for fb in pending:
            fb.used_in_retrain = True
        db.session.commit()

        # Updates this worker process's in-memory model; the web process(es)
        # pick up the new version lazily on their next classify() call via
        # ml.infer._ensure_current() (see ml/infer.py) since current.json
        # changed -- reload() here is not what makes the web process see it.
        infer.reload()
        log_action(actor, "retrain_model", target=version, details=notes)
        return {"version": version, "metrics": metrics, "meta": meta}
