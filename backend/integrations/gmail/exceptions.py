"""
Gmail integration error hierarchy.

Split by whether the caller should retry (transient) or give up and
surface the problem (permanent / needs re-auth), so Celery tasks and route
handlers can make that decision from the exception type alone rather than
string-matching messages.
"""


class GmailError(Exception):
    """Base class for every Gmail-integration failure."""


class GmailConfigError(GmailError):
    """OAuth client / redirect URI not configured in the environment."""


class GmailOAuthError(GmailError):
    """OAuth handshake failed (bad state, denied consent, code exchange
    error). Permanent for this attempt -- the user must retry the flow."""


class GmailAuthError(GmailError):
    """Stored credentials are no longer usable (revoked / invalid_grant).
    The mailbox must be reconnected -- not retryable."""


class GmailRetryableError(GmailError):
    """Transient failure (rate limit, 5xx, network). Safe to retry with
    backoff."""


class GmailPermanentError(GmailError):
    """Non-retryable API failure (4xx that isn't auth/rate-limit)."""


class GmailHistoryExpiredError(GmailError):
    """The stored startHistoryId is too old / invalid (Gmail 404 on
    history.list). The caller must fall back to a bounded message list and
    re-baseline the history id -- not an error to surface to the admin."""


class GmailNotFoundError(GmailPermanentError):
    """A specific message/label no longer exists (Gmail 404). Safe to skip
    -- e.g. the user deleted the message before Sentinel processed it."""
