"""
Tests for the promote/rollback model-governance flow: training produces a
reviewable candidate only, and POST /api/admin/model-version/<v>/promote
is the one action that changes what classify() actually serves -- same
mechanism whether promoting the newest candidate or rolling back to an
older version.

Retraining a real model takes ~40s (see ml/train.py), far too slow for a
test suite, so:
- test_retrain_task_does_not_promote mocks ml.train.train() to return
  instantly, verifying tasks.py's DB-writing behavior in isolation.
- The promote/rollback tests reuse the real v1 artifacts (copied, not
  touched) but write into a throwaway temp directory that ml.infer.ARTIFACTS_DIR
  is monkeypatched to point at -- NOT the real backend/ml/artifacts/, which
  is live local-dev state (its current.json controls what a real `python
  app.py` run actually serves). An earlier version of this test wrote
  directly into the real directory and clobbered the real current.json;
  this fixture exists specifically to never do that again.
"""

import json
import os
import shutil
from unittest.mock import patch

import pytest

from models import ModelVersion
from extensions import db
from ml import infer


REAL_ARTIFACTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml", "artifacts"
)


@pytest.fixture()
def fake_second_version(app, tmp_path, monkeypatch):
    """
    Isolated artifacts dir (tmp_path) containing v1 (copied from the real
    one) and a throwaway 'vtest2' candidate (also copied from v1 -- its
    actual weights don't matter for these tests, only that promote() can
    load *some* real joblib files). ml.infer.ARTIFACTS_DIR is monkeypatched
    to this temp dir for the duration of the test, so promote() -- which
    reads/writes ARTIFACTS_DIR/current.json -- never touches the real
    local-dev artifacts directory. monkeypatch auto-reverts after the test.
    """
    monkeypatch.setattr(infer, "ARTIFACTS_DIR", str(tmp_path))
    shutil.copytree(os.path.join(REAL_ARTIFACTS_DIR, "v1"), str(tmp_path / "v1"))
    shutil.copytree(os.path.join(REAL_ARTIFACTS_DIR, "v1"), str(tmp_path / "vtest2"))
    (tmp_path / "current.json").write_text(json.dumps({"version": "v1"}))

    with app.app_context():
        db.session.add(
            ModelVersion(
                version="vtest2",
                accuracy=0.9,
                precision=0.9,
                recall=0.9,
                f1_score=0.9,
                false_positive_rate=0.1,
                false_negative_rate=0.1,
                n_train=100,
                n_test=20,
                n_feedback_folded_in=0,
                notes="test candidate",
                is_current=False,
            )
        )
        db.session.add(
            ModelVersion(
                version="v1",
                accuracy=0.96,
                precision=0.95,
                recall=0.97,
                f1_score=0.96,
                false_positive_rate=0.05,
                false_negative_rate=0.03,
                n_train=30000,
                n_test=7500,
                n_feedback_folded_in=0,
                notes="baseline",
                is_current=True,
            )
        )
        db.session.commit()

    infer._state.update(
        version=None
    )  # force a fresh load against the patched ARTIFACTS_DIR
    yield "vtest2"
    infer._state.update(
        version=None
    )  # don't leak the temp-dir-backed state into later tests


def test_retrain_task_does_not_promote(app, admin_client):
    with app.app_context():
        before = infer.current_info()["version"]

        fake_metrics = {
            "accuracy": 0.9,
            "precision": 0.9,
            "recall": 0.9,
            "f1_score": 0.9,
            "false_positive_rate": 0.1,
            "false_negative_rate": 0.1,
            "n_train": 100,
            "n_test": 20,
        }
        with patch(
            "ml.train.train",
            return_value=("vfake", fake_metrics, {"n_samples_total": 120}),
        ):
            from tasks import retrain_task

            result = retrain_task.run("admin")

        assert result["version"] == "vfake"
        mv = db.session.get(ModelVersion, "vfake")
        assert mv is not None
        assert mv.is_current is False  # trained, not promoted
        assert infer.current_info()["version"] == before  # live model unchanged

        ModelVersion.query.filter_by(version="vfake").delete()
        db.session.commit()


def test_promote_makes_version_live(admin_client, fake_second_version):
    resp = admin_client.post(f"/api/admin/model-version/{fake_second_version}/promote")
    assert resp.status_code == 200
    assert infer.current_info()["version"] == fake_second_version

    from app import app as flask_app

    with flask_app.app_context():
        assert db.session.get(ModelVersion, fake_second_version).is_current is True
        assert db.session.get(ModelVersion, "v1").is_current is False


def test_promote_older_version_is_rollback(admin_client, fake_second_version):
    admin_client.post(f"/api/admin/model-version/{fake_second_version}/promote")
    assert infer.current_info()["version"] == fake_second_version

    # Rolling back is just promoting the older version again -- no
    # separate rollback endpoint.
    resp = admin_client.post("/api/admin/model-version/v1/promote")
    assert resp.status_code == 200
    assert infer.current_info()["version"] == "v1"

    from app import app as flask_app

    with flask_app.app_context():
        assert db.session.get(ModelVersion, "v1").is_current is True
        assert db.session.get(ModelVersion, fake_second_version).is_current is False


def test_promote_requires_admin(user_client, fake_second_version):
    resp = user_client.post(f"/api/admin/model-version/{fake_second_version}/promote")
    assert resp.status_code == 403


def test_promote_requires_login(client, fake_second_version):
    resp = client.post(f"/api/admin/model-version/{fake_second_version}/promote")
    assert resp.status_code == 401


def test_promote_unknown_version_404s(admin_client):
    resp = admin_client.post("/api/admin/model-version/v_does_not_exist/promote")
    assert resp.status_code == 404
