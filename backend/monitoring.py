"""
Optional Sentry error tracking. Gated by SENTRY_DSN exactly like
MailConfig/MailboxConfig/artifact_store: unset means a complete no-op (no
import cost beyond the cheap sentry_sdk import, no behavior change), so
this is fully safe to call in every environment including local dev and
CI, and only actually reports anything once a real DSN is configured at
deploy time.
"""

import os


def init_sentry(extra_integrations=None):
    dsn = os.environ.get("SENTRY_DSN")
    if not dsn:
        return

    import sentry_sdk

    sentry_sdk.init(
        dsn=dsn,
        environment=os.environ.get("SENTINEL_ENV", "development"),
        traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0")),
        integrations=extra_integrations or [],
    )
