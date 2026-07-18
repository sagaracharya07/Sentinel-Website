"""
Shared Flask extension singletons.

These are constructed here (unbound) and bound to the app in app.py via
init_app(), rather than being created against the app object directly.
That's what lets blueprints and service modules (e.g. routes/gmail.py)
import `db`, `csrf`, and `limiter` without importing app.py and creating a
circular import. app.py re-exports them for backward compatibility with
existing imports (`from app import limiter` in the test suite).
"""

from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
csrf = CSRFProtect()

# Storage is configured via app.config["RATELIMIT_STORAGE_URI"] in app.py
# (Redis when REDIS_URL is set, in-memory otherwise) -- not passed here,
# since this instance is created before any app exists.
limiter = Limiter(key_func=get_remote_address, default_limits=[])
