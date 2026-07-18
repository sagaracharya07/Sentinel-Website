"""
One-time startup seeding step. Run once (see Dockerfile's CMD chain:
alembic upgrade head && python seed_startup.py && gunicorn ...) BEFORE
gunicorn spawns its worker processes -- not from wsgi.py itself.

Multiple gunicorn workers each importing wsgi.py concurrently would each
call ensure_seed_data() independently, racing on the same INSERT (e.g.
ModelVersion's primary key) with no locking between them. That's not
hypothetical: it's exactly what crashed the whole gunicorn master the
first time this was tried as an import-time call in wsgi.py, so seeding
now happens as its own one-shot step instead.
"""

from app import app, ensure_seed_data

with app.app_context():
    ensure_seed_data()
