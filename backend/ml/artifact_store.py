"""
S3-compatible object storage for trained model artifacts.

Retraining runs on the Celery worker, but the web service is what needs to
serve the resulting model. In docker-compose, web/worker/beat share a
volume for ml/artifacts/ (see docker-compose.yml) because they're all on
one Docker host -- but Render (and most PaaS providers) runs each as a
genuinely separate service with its own disk, with no equivalent. Object
storage is the provider-agnostic fix: the worker uploads a version's files
after training, and any process (web, worker, beat) downloads/caches a
version's files locally the first time it needs them.

Works with AWS S3, Cloudflare R2, Backblaze B2, MinIO, or anything else
speaking the S3 API. Configure via env vars:
  ARTIFACT_STORE_BUCKET             (required -- unset disables this whole
                                      module; everything becomes a no-op
                                      and ml/train.py + ml/infer.py fall
                                      back to local-filesystem-only, which
                                      is correct for docker-compose)
  ARTIFACT_STORE_ENDPOINT_URL       (omit for real AWS S3; set for
                                      R2/B2/MinIO/etc -- e.g.
                                      http://minio:9000 for local dev)
  ARTIFACT_STORE_ACCESS_KEY_ID
  ARTIFACT_STORE_SECRET_ACCESS_KEY
  ARTIFACT_STORE_REGION             (default: us-east-1 -- required by the
                                      S3 API even when the provider doesn't
                                      really have regions, e.g. MinIO)
"""
import os
import json

ARTIFACT_FILES = ["tfidf_vectorizer.joblib", "scaler.joblib", "model.joblib", "meta.json", "metrics.json"]


def enabled():
    return bool(os.environ.get("ARTIFACT_STORE_BUCKET"))


def _bucket():
    return os.environ["ARTIFACT_STORE_BUCKET"]


def _client():
    import boto3
    return boto3.client(
        "s3",
        endpoint_url=os.environ.get("ARTIFACT_STORE_ENDPOINT_URL") or None,
        aws_access_key_id=os.environ.get("ARTIFACT_STORE_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("ARTIFACT_STORE_SECRET_ACCESS_KEY"),
        region_name=os.environ.get("ARTIFACT_STORE_REGION", "us-east-1"),
    )


def _ensure_bucket(client):
    try:
        client.create_bucket(Bucket=_bucket())
    except Exception:
        pass  # already exists (the common case) or we don't have create permission -- either way, proceed


def upload_version(version_dir: str, version: str):
    """Uploads one version's artifact files, then updates the remote
    pointer -- in that order, so no other process can ever see a pointer
    referencing a version whose files aren't fully uploaded yet."""
    if not enabled():
        return
    client = _client()
    _ensure_bucket(client)
    for fname in ARTIFACT_FILES:
        client.upload_file(os.path.join(version_dir, fname), _bucket(), f"{version}/{fname}")
    client.put_object(Bucket=_bucket(), Key="current.json", Body=json.dumps({"version": version}).encode())


def remote_pointer_version():
    """The version the remote store's current.json points at, or None if
    object storage isn't configured or nothing's been uploaded yet."""
    if not enabled():
        return None
    import botocore
    client = _client()
    try:
        obj = client.get_object(Bucket=_bucket(), Key="current.json")
        return json.loads(obj["Body"].read())["version"]
    except botocore.exceptions.ClientError:
        return None


def download_version(version_dir: str, version: str):
    """Downloads a version's artifact files into version_dir, skipping
    any file that's already cached locally (immutable once trained, so a
    local file never needs to be re-fetched)."""
    if not enabled():
        return
    client = _client()
    os.makedirs(version_dir, exist_ok=True)
    for fname in ARTIFACT_FILES:
        local_path = os.path.join(version_dir, fname)
        if os.path.exists(local_path):
            continue
        client.download_file(_bucket(), f"{version}/{fname}", local_path)
