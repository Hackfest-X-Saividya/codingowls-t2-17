FROM python:3.12-slim

# System deps: git (for gitpython); npm regenerates package-lock.json when validating npm dependency fixes
RUN apt-get update && apt-get install -y \
    git \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep in an isolated environment via pipx to avoid
# Pydantic version conflicts with the app
RUN pip install --no-cache-dir pipx \
    && pipx install semgrep \
    && pipx ensurepath
ENV PATH="/root/.local/bin:$PATH"

# Verify semgrep works
RUN semgrep --version

# App setup
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV TEMP_DIR=/tmp/security_scans

EXPOSE 8000

# Railway injects $PORT at runtime; fall back to 8000 locally
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
