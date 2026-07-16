# Built from the REPO ROOT as build context (see docker-compose.yml /
# render.yaml: `context: .`, `dockerfile: backend/Dockerfile`) because
# app.py serves site/ as static files via a relative "../site" path from
# backend/ -- the image needs both directories in that same relative
# layout, not just backend/ in isolation.
#
# Single image used for all three backend roles (web, celery worker,
# celery beat); docker-compose.yml/render.yaml override CMD per service.
FROM python:3.14-slim

WORKDIR /app/backend

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
COPY site/ /app/site/

EXPOSE 5000

# Default to the web role; docker-compose.yml/render.yaml override this
# command for the worker and beat services. Migrations and seeding are
# one-shot steps run before gunicorn spawns any workers -- see
# seed_startup.py for why seeding can't just happen at wsgi.py import time.
CMD ["sh", "-c", "alembic upgrade head && python seed_startup.py && gunicorn -b 0.0.0.0:5000 -w 2 wsgi:app"]
