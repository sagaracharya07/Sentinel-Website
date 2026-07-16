"""
Loads whichever model version is current, and exposes a single classify()
function used by the /api/scan route. Reloadable at runtime (reload()) so
/api/admin/retrain can hot-swap in a newly retrained model without
restarting the Flask process -- satisfies NFR-Maintainability ("retrain
and redeploy without downtime").

"Current" comes from the object store (artifact_store.py) when one's
configured (ARTIFACT_STORE_BUCKET), since that's the only thing web,
worker, and beat all actually share when they're separate services with
separate disks (e.g. on Render). Falls back to the local
ml/artifacts/current.json file when object storage isn't configured --
correct for docker-compose, which shares ml/artifacts/ via a volume
instead (see docker-compose.yml).
"""
import os
import json
import joblib
import pandas as pd

from ml.train import build_feature_matrix
from ml import artifact_store

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS_DIR = os.path.join(HERE, "artifacts")

_state = {"version": None, "vectorizer": None, "scaler": None, "model": None, "meta": None, "metrics": None}


def _load_version(version):
    version_dir = os.path.join(ARTIFACTS_DIR, version)
    artifact_store.download_version(version_dir, version)  # no-op if not configured or already cached
    vectorizer = joblib.load(os.path.join(version_dir, "tfidf_vectorizer.joblib"))
    scaler = joblib.load(os.path.join(version_dir, "scaler.joblib"))
    model = joblib.load(os.path.join(version_dir, "model.joblib"))
    with open(os.path.join(version_dir, "meta.json")) as f:
        meta = json.load(f)
    with open(os.path.join(version_dir, "metrics.json")) as f:
        metrics = json.load(f)
    return vectorizer, scaler, model, meta, metrics


def _local_pointer_version():
    with open(os.path.join(ARTIFACTS_DIR, "current.json")) as f:
        return json.load(f)["version"]


def _pointer_version():
    # The remote pointer is only meaningful once something's actually been
    # uploaded to it -- on a fresh deploy before any retrain, nothing has,
    # so fall back to the locally baked-in version (whatever v1 shipped in
    # the image/repo).
    return artifact_store.remote_pointer_version() or _local_pointer_version()


def reload():
    version = _pointer_version()
    vectorizer, scaler, model, meta, metrics = _load_version(version)
    _state.update(version=version, vectorizer=vectorizer, scaler=scaler,
                  model=model, meta=meta, metrics=metrics)
    return version


def _ensure_current():
    """
    Retraining runs in a separate Celery worker process (see
    backend/tasks.py), so its in-process reload() call doesn't touch this
    process's _state -- only the worker's. Any process serving classify()
    calls (the Flask web process(es)) needs to notice current.json changed
    and reload for itself. current.json is a few bytes, so checking it on
    every call is cheap next to the classification work itself.
    """
    if _state["version"] is None or _state["version"] != _pointer_version():
        reload()


def current_info():
    _ensure_current()
    return {"version": _state["version"], "meta": _state["meta"], "metrics": _state["metrics"]}


def classify(subject: str, body: str, sender: str = ""):
    """
    Runs the full FR-SE-05..08 pipeline for one email: preprocessing ->
    feature extraction -> Random Forest classification -> confidence
    score + risk band + explainable findings. Returns a dict ready to be
    persisted (Scan row) and returned to the front-end as JSON.
    """
    _ensure_current()

    from ml.features import engineered_features

    row_df = pd.DataFrame([{"subject": subject or "", "body": body or "", "sender": sender or ""}])
    X, _, _ = build_feature_matrix(row_df, vectorizer=_state["vectorizer"],
                                    scaler=_state["scaler"], fit=False)

    model = _state["model"]
    proba = model.predict_proba(X)[0]
    classes = list(model.classes_)
    phishing_idx = classes.index(1) if 1 in classes else len(classes) - 1
    phishing_proba = float(proba[phishing_idx])

    label = "Phishing" if phishing_proba >= 0.5 else "Legitimate"
    score = round(phishing_proba * 100)
    if score >= 70:
        risk_level = "High"
    elif score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    _, findings, highlights = engineered_features(subject, body, sender)

    return {
        "label": label,
        "confidence": round(phishing_proba, 4),
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "highlights": highlights,
        "model_version": _state["version"],
    }
