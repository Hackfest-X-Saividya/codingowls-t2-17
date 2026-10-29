# Packaging for Railway / Fly.io only. The checker itself never starts containers and never
# runs the scanned code: one Python process serves the page and checks repositories in-request.
FROM python:3.13-slim

# git clones the repositories; Node parses JavaScript files (optional, skipped if missing)
RUN apt-get update && apt-get install -y --no-install-recommends git nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY checker.py server.py ./
COPY static ./static

# Cloned repositories are untrusted input: handle them as an unprivileged user
RUN useradd --create-home checker
USER checker

ENV HOST=0.0.0.0 \
    PORT=8080 \
    PYTHONUNBUFFERED=1
EXPOSE 8080

# Railway injects $PORT; Fly uses internal_port 8080 from fly.toml
CMD ["python", "server.py"]
