"""
Loads whichever model version is current, and exposes a single classify()
function used by the /api/scan route. promote(version) hot-swaps a new
current version in at runtime -- no restart needed, satisfying
NFR-Maintainability ("retrain and redeploy without downtime") -- but only
promote() does that. Retraining alone (ml/train.py, triggered via
/api/admin/retrain) produces a reviewable candidate model and never
changes what's live on its own; an admin must explicitly promote a
version (POST /api/admin/model-version/<version>/promote) for it to take
effect, which is also how a rollback to an older version works.

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


def promote(version: str) -> str:
    """
    The only function that changes what classify() actually serves.
    Training (ml/train.py) only ever produces a reviewable candidate;
    this is the explicit, human-triggered action (POST
    /api/admin/model-version/<version>/promote) that makes one version
    live. Works identically whether `version` is the newest trained
    candidate (the normal case) or an older, previously-live one (a
    rollback) -- there's no separate rollback code path.

    _load_version() raises if the version's files are missing or corrupt
    (e.g. a typo'd version string, or artifacts that never finished
    uploading) -- deliberately not caught here, so a bad promote request
    fails loudly instead of silently leaving the old model in place while
    claiming success.
    """
    vectorizer, scaler, model, meta, metrics = _load_version(version)

    with open(os.path.join(ARTIFACTS_DIR, "current.json"), "w") as f:
        json.dump({"version": version}, f)
    artifact_store.set_current_version(version)

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


def decide(phishing_proba: float):
    """
    Three-state operational decision from a raw phishing probability.

    A flat 0.5 cutoff meant a message the model was only 63% sure about
    got the same "Phishing" label -- and the same weight in the UI -- as
    one it was 99% sure about, which produced misleading verdicts on
    borderline mail. Splitting the middle band into "Needs Review" makes
    that uncertainty visible instead of silently rounding it down to
    "Legitimate" or up to "Phishing".

        >= 0.75  -> Phishing      (High risk)   -- quarantine
        >= 0.50  -> Needs Review  (Medium risk) -- flag, do not quarantine
        <  0.50  -> Legitimate    (Low risk)    -- no action
    """
    if phishing_proba >= 0.75:
        return "Phishing", "High"
    if phishing_proba >= 0.50:
        return "Needs Review", "Medium"
    return "Legitimate", "Low"


def classify(subject: str, body: str, sender: str = ""):
    """
    Runs the full FR-SE-05..08 pipeline for one email: preprocessing ->
    feature extraction -> Random Forest classification -> probability +
    risk band + explainable findings. Returns a dict ready to be
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

    label, risk_level = decide(phishing_proba)
    score = round(phishing_proba * 100)

    # prediction_confidence is how sure the model is of *whichever* label
    # it picked -- not the same thing as phishing_probability. A message
    # at 5% phishing probability is 95%-confidently legitimate, not
    # "5% confident"; conflating the two under one "confidence" number
    # was misleading for anything below the phishing threshold.
    prediction_confidence = max(phishing_proba, 1 - phishing_proba)

    _, findings, highlights = engineered_features(subject, body, sender)

    return {
        "label": label,
        "phishing_probability": round(phishing_proba, 4),
        "prediction_confidence": round(prediction_confidence, 4),
        "confidence": round(phishing_proba, 4),  # deprecated alias of phishing_probability, kept for backward compat
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "highlights": highlights,
        "model_version": _state["version"],
    }
