# Minimal by design: a Python base and this repo. No dependency tree to audit,
# which is a peculiar thing to get wrong in a supply-chain security tool.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    REDHAND_CACHE=/tmp/redhand-cache

WORKDIR /srv
COPY redhand/ ./redhand/
COPY server/app.py ./server/app.py

# Run unprivileged. /tmp is the only writable path the process needs, and it
# holds nothing but the public KEV feed cache.
RUN useradd --system --uid 10001 redhand \
 && mkdir -p /tmp/redhand-cache \
 && chown -R redhand:redhand /srv /tmp/redhand-cache
USER redhand

EXPOSE 8080
CMD ["python", "-u", "server/app.py"]
