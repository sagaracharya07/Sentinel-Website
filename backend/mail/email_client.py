"""
Outbound email for Sentinel -- account verification, password reset, and
the contact form. Mirrors mailbox/imap_client.py's MailboxConfig.from_env()
pattern exactly: configuration lives in environment variables, and
send_email() degrades gracefully (never raises) when unconfigured, so
local dev/testing never needs real credentials.

Uses stdlib smtplib rather than a third-party transactional-email SDK, so
this needs no new pip dependency and works with a plain SMTP app password
(Gmail, etc) -- the same credential model the mailbox reader already uses,
just for a "send" scope instead of "read". Swapping in a transactional API
provider later would only mean rewriting send_email()'s body; MailConfig
and every caller stays the same.
"""
import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Optional


@dataclass
class MailConfig:
    host: str
    port: int
    from_address: str
    username: Optional[str] = None
    password: Optional[str] = None
    use_tls: bool = True
    use_auth: bool = True

    @classmethod
    def from_env(cls) -> Optional["MailConfig"]:
        # Only MAIL_HOST is truly required -- a local no-auth SMTP catcher
        # (Mailpit, used for local verification -- see docker-compose.yml)
        # needs no username/password/TLS at all, unlike a real provider.
        host = os.environ.get("MAIL_HOST")
        if not host:
            return None
        return cls(
            host=host,
            port=int(os.environ.get("MAIL_PORT", "587")),
            from_address=os.environ.get("MAIL_FROM_ADDRESS", "noreply@sentinel.local"),
            username=os.environ.get("MAIL_USERNAME") or None,
            password=os.environ.get("MAIL_PASSWORD") or None,
            use_tls=os.environ.get("MAIL_USE_TLS", "true").lower() != "false",
            use_auth=os.environ.get("MAIL_USE_AUTH", "true").lower() != "false",
        )


def public_base_url() -> str:
    """Used to build links (verification, reset) inside emails."""
    return os.environ.get("SENTINEL_PUBLIC_BASE_URL", "http://localhost:5000").rstrip("/")


def send_email(to: str, subject: str, html_body: str) -> bool:
    """
    Sends one email. Returns True on send (or dev-mode no-op), False on a
    real send failure -- callers should treat False as "log it and move
    on", never as a reason to fail the request that triggered the email
    (e.g. registration should still succeed even if the verification email
    couldn't be sent; the user can use a resend-verification path later).

    Dev-mode fallback: when MailConfig.from_env() is unset (no real SMTP
    configured), this logs the email instead of sending -- so
    registration/verification/reset/contact are all fully testable
    locally with zero credentials, same as MailboxConfig's graceful
    degradation when no real mailbox is configured.
    """
    cfg = MailConfig.from_env()
    if not cfg:
        print(f"[DEV MODE: no MAIL_HOST configured] Email to {to!r}: {subject!r}\n{html_body}")
        return True

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.from_address
    msg["To"] = to
    msg.set_content("This email requires an HTML-capable client to view.")
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(cfg.host, cfg.port, timeout=10) as smtp:
            if cfg.use_tls:
                smtp.starttls(context=ssl.create_default_context())
            if cfg.use_auth and cfg.username and cfg.password:
                smtp.login(cfg.username, cfg.password)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"send_email failed: {e}")
        return False
