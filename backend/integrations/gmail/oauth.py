"""
Google OAuth 2.0 handshake for connecting a Gmail mailbox.

Pure, route-independent helpers: build the consent URL, exchange the
callback code for tokens, and identify the connected Google account. The
Flask blueprint (routes/gmail.py) owns session/state storage and the DB;
this module owns the Google protocol details.

Scopes requested (minimum for the product, each justified):
  - openid                              : returns a stable account id (sub)
  - .../auth/userinfo.email             : confirm *which* mailbox was connected
  - .../auth/gmail.modify               : read messages + add/remove labels
                                          (quarantine = add Quarantine label +
                                          remove INBOX; release = the reverse).
                                          gmail.modify cannot permanently
                                          delete mail, which is exactly the
                                          guarantee this product wants.

We deliberately do NOT request gmail.readonly (can't label) or the full
https://mail.google.com/ scope (allows permanent deletion).
"""

import os

# Google frequently returns the granted scopes in a different order and adds
# 'openid' implicitly, which makes oauthlib's strict equality check raise
# "Scope has changed". Relaxing it here (before oauthlib is imported by the
# google libs) accepts an equivalent-but-reordered scope set. We still
# record the actually-granted scopes on the connection for auditing.
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

from google_auth_oauthlib.flow import Flow  # noqa: E402
from google.oauth2.credentials import Credentials  # noqa: E402
from google.auth.transport.requests import AuthorizedSession  # noqa: E402

from .exceptions import GmailConfigError, GmailOAuthError  # noqa: E402

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.modify",
]

USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
_TOKEN_URI = "https://oauth2.googleapis.com/token"


def client_id() -> str | None:
    return os.environ.get("GOOGLE_CLIENT_ID")


def redirect_uri() -> str | None:
    return os.environ.get("GOOGLE_OAUTH_REDIRECT_URI")


def is_configured() -> bool:
    """True only if every OAuth client value needed to run the flow is set."""
    return bool(
        os.environ.get("GOOGLE_CLIENT_ID")
        and os.environ.get("GOOGLE_CLIENT_SECRET")
        and os.environ.get("GOOGLE_OAUTH_REDIRECT_URI")
    )


def _client_config() -> dict:
    if not is_configured():
        raise GmailConfigError(
            "Google OAuth is not configured -- set GOOGLE_CLIENT_ID, "
            "GOOGLE_CLIENT_SECRET and GOOGLE_OAUTH_REDIRECT_URI "
            "(see backend/.env.example)."
        )
    return {
        "web": {
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "auth_uri": _AUTH_URI,
            "token_uri": _TOKEN_URI,
            "redirect_uris": [os.environ["GOOGLE_OAUTH_REDIRECT_URI"]],
        }
    }


def build_flow(state: str | None = None) -> Flow:
    return Flow.from_client_config(
        _client_config(),
        scopes=SCOPES,
        state=state,
        redirect_uri=os.environ["GOOGLE_OAUTH_REDIRECT_URI"],
    )


def authorization_url(state: str) -> str:
    """Build the Google consent URL for a caller-supplied (and separately
    stored) `state`. access_type=offline + prompt=consent guarantees Google
    returns a refresh token, even on a repeat authorisation of an account
    that previously granted access -- without prompt=consent, a re-auth
    often omits the refresh token and we'd have no way to keep access."""
    flow = build_flow(state=state)
    url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    return url


def exchange_code(code: str, state: str) -> Credentials:
    """Exchange the authorization code from the callback for credentials
    (access + refresh token). Raises GmailOAuthError on any failure so the
    route can render a safe error instead of a stack trace."""
    try:
        flow = build_flow(state=state)
        flow.fetch_token(code=code)
        return flow.credentials
    except Exception as e:
        raise GmailOAuthError(f"Could not exchange authorization code: {e}") from e


def fetch_userinfo(credentials: Credentials) -> dict:
    """Identify the connected Google account (email + stable sub). Used to
    label the connection and to verify which mailbox was actually granted."""
    try:
        resp = AuthorizedSession(credentials).get(USERINFO_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        raise GmailOAuthError(f"Could not retrieve Google account info: {e}") from e
    email = data.get("email")
    if not email:
        raise GmailOAuthError("Google account info did not include an email address")
    return {
        "email": email,
        "sub": data.get("sub"),
        "email_verified": data.get("email_verified", False),
    }


def credentials_to_storage(credentials: Credentials) -> dict:
    """Flatten Credentials into the fields GmailConnection stores. Tokens are
    returned in plaintext here; the model encrypts them before persisting."""
    return {
        "refresh_token": credentials.refresh_token,
        "access_token": credentials.token,
        "token_expiry": credentials.expiry,  # naive UTC datetime or None
        "scopes": " ".join(credentials.scopes or SCOPES),
    }
