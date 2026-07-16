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
# command for the worker and beat services.
CMD ["sh", "-c", "alembic upgrade head && gunicorn -b 0.0.0.0:5000 -w 2 wsgi:app"]
