"""
Trains the Random Forest phishing classifier described in the proposal
(Section 2.2 FR-SE-07, pseudocode 6.5 ScanEmailWithAI) and saves a
versioned set of artifacts under ml/artifacts/<version>/:

  - tfidf_vectorizer.joblib
  - scaler.joblib
  - model.joblib
  - metrics.json     (accuracy, precision, recall, f1, confusion matrix,
                       dataset size -- the real numbers behind the
                       NFR-Accuracy claims in the proposal)
  - meta.json         (version, trained_at, n_samples, notes)

Deliberately does NOT promote the version it trains to "current" --
training produces a reviewable candidate; ml/infer.py's promote()
(triggered via POST /api/admin/model-version/<version>/promote) is the
only thing that ever changes what ml/infer.py's classify() actually
serves. This is what makes a bad retrain reviewable instead of silently
going live, and what makes rolling back to an older version possible
(promote is not "promote the newest one," it's "promote this specific
version," so an older one works too).

Run: python3 -m ml.train             (from the backend/ directory)
"""

import os
import json
import time
import logging
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from ml.features import engineered_features, NUMERIC_FEATURE_NAMES
from ml import artifact_store

logger = logging.getLogger(__name__)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "..", "data")
ARTIFACTS_DIR = os.path.join(HERE, "artifacts")


def build_feature_matrix(df, vectorizer=None, scaler=None, fit=True):
    text = (df["subject"].fillna("") + " \n " + df["body"].fillna("")).tolist()

    if fit:
        vectorizer = TfidfVectorizer(
            max_features=3500,
            ngram_range=(1, 2),
            min_df=3,
            sublinear_tf=True,
            stop_words="english",
        )
        tfidf = vectorizer.fit_transform(text)
    else:
        tfidf = vectorizer.transform(text)

    numeric_rows = []
    for _, row in df.iterrows():
        nums, _, _ = engineered_features(
            row.get("subject", ""), row.get("body", ""), row.get("sender", "")
        )
        numeric_rows.append(nums)
    numeric = np.array(numeric_rows, dtype=float)

    if fit:
        scaler = StandardScaler()
        numeric_scaled = scaler.fit_transform(numeric)
    else:
        numeric_scaled = scaler.transform(numeric)

    X = sparse.hstack([tfidf, sparse.csr_matrix(numeric_scaled)]).tocsr()
    return X, vectorizer, scaler


def next_version():
    """
    Takes the max of two sources -- the artifacts directory AND the
    model_versions table, when a DB/app context is available -- rather
    than trusting the filesystem alone. Those two can drift (verified
    while testing the multi-container Docker setup: retraining from a
    worker container whose ml/artifacts/ wasn't yet on a volume shared
    with web left a model_versions row for a version whose files never
    existed anywhere durable; the next retrain recomputed the same
    version name from the filesystem and hit a duplicate-key crash on
    the now-stale DB row). Falls back to filesystem-only when there's no
    app context, e.g. the standalone `python -m ml.train` CLI path.
    """
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    existing = [d for d in os.listdir(ARTIFACTS_DIR) if d.startswith("v")]
    nums = []
    for d in existing:
        try:
            nums.append(int(d[1:]))
        except ValueError:
            pass

    try:
        from models import ModelVersion

        for row in ModelVersion.query.with_entities(ModelVersion.version).all():
            v = row[0]
            if v.startswith("v"):
                try:
                    nums.append(int(v[1:]))
                except ValueError:
                    pass
    except Exception:
        pass  # no app/DB context (standalone CLI) -- filesystem-only is fine there

    return f"v{(max(nums) + 1) if nums else 1}"


def train(extra_df: pd.DataFrame = None, notes: str = "Initial training run"):
    """
    extra_df: optional DataFrame of confirmed user/admin feedback
    (sender, subject, body, label) to fold into training -- this is what
    ml/retrain.py passes in to implement the feedback/retraining loop
    (UC-07, pseudocode 6.9).
    """
    df = pd.read_csv(os.path.join(DATA_DIR, "combined_dataset.csv"))
    if extra_df is not None and len(extra_df):
        df = pd.concat(
            [df, extra_df[["sender", "subject", "body", "label"]]], ignore_index=True
        )
        df = df.drop_duplicates(subset=["subject", "body"], keep="last")

    train_df, test_df = train_test_split(
        df, test_size=0.2, random_state=42, stratify=df["label"]
    )

    t0 = time.time()
    X_train, vectorizer, scaler = build_feature_matrix(train_df, fit=True)
    X_test, _, _ = build_feature_matrix(
        test_df, vectorizer=vectorizer, scaler=scaler, fit=False
    )
    y_train, y_test = train_df["label"].values, test_df["label"].values

    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=22,
        min_samples_leaf=3,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train, y_train)
    train_seconds = round(time.time() - t0, 2)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred).tolist()  # [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    false_negative_rate = fn / (fn + tp) if (fn + tp) else 0.0

    version = next_version()
    version_dir = os.path.join(ARTIFACTS_DIR, version)
    os.makedirs(version_dir, exist_ok=True)

    joblib.dump(vectorizer, os.path.join(version_dir, "tfidf_vectorizer.joblib"))
    joblib.dump(scaler, os.path.join(version_dir, "scaler.joblib"))
    joblib.dump(clf, os.path.join(version_dir, "model.joblib"))

    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "n_train": len(train_df),
        "n_test": len(test_df),
        "train_seconds": train_seconds,
    }
    meta = {
        "version": version,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_samples_total": len(df),
        "n_feedback_folded_in": 0 if extra_df is None else len(extra_df),
        "notes": notes,
        "feature_dim": X_train.shape[1],
        "numeric_feature_names": NUMERIC_FEATURE_NAMES,
    }
    with open(os.path.join(version_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    with open(os.path.join(version_dir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    # Deliberately does NOT touch current.json / the remote pointer --
    # training produces a reviewable candidate, not a live model. Call
    # ml.infer.promote(version) (or POST /api/admin/model-version/<v>/promote)
    # to actually put it in front of traffic. See ml/infer.py's promote()
    # docstring for why this split exists.
    artifact_store.upload_version(version_dir, version)

    logger.info(
        "Trained %s: acc=%.4f precision=%.4f recall=%.4f f1=%.4f FPR=%.4f FNR=%.4f (%ss, %s samples)",
        version,
        acc,
        prec,
        rec,
        f1,
        false_positive_rate,
        false_negative_rate,
        train_seconds,
        len(df),
    )
    return version, metrics, meta


if __name__ == "__main__":
    train()
