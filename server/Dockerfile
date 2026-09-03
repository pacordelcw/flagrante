# Minimal by design: a Python base and this repo. No dependency tree to audit,
# which is a peculiar thing to get wrong in a supply-chain security tool.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLAGRANTE_CACHE=/tmp/flagrante-cache

WORKDIR /srv
COPY flagrante/ ./flagrante/
COPY server/app.py ./server/app.py

# Run unprivileged. /tmp is the only writable path the process needs, and it
# holds nothing but the public KEV feed cache.
RUN useradd --system --uid 10001 flagrante \
 && mkdir -p /tmp/flagrante-cache \
 && chown -R flagrante:flagrante /srv /tmp/flagrante-cache
USER flagrante

EXPOSE 8080
CMD ["python", "-u", "server/app.py"]
