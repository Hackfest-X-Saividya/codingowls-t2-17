# Setup Guide

## Live Demo

- **Frontend**: Hosted on Vercel
- **Backend**: Hosted on Railway

## Prerequisites (Local Development)

- **Python 3.12** — Backend runtime (the version the Dockerfile uses)
- **Node.js 18+** — Frontend runtime
- **Semgrep** — Static analysis engine (installed via pip)
- **Git** — For cloning target repositories
- **MongoDB** — Stores the fix-validation attempt history (MongoDB Atlas or a local server); needed for Validate Fix
- **Groq API Key** (optional) — For AI-enhanced explanations and AI fix suggestions

## 1. Install Semgrep

```bash
pip install semgrep
```

Verify installation:
```bash
semgrep --version
```

## 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (includes semgrep)
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env:
#   MONGODB_URI / MONGODB_DATABASE  required for Validate Fix (see "MongoDB" below)
#   GROQ_API_KEY                    optional but recommended

# Start the server
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.

### MongoDB (validation history)

Every Validate Fix attempt is stored in MongoDB. Without `MONGODB_URI` the scanner still works, but
Validate Fix answers `503` with these instructions; there is no fallback store.

- **MongoDB Atlas:** in Atlas, create a database user and add your IP (or the server's) under
  *Network Access*. Then copy the connection string from *Connect → Drivers*:
  ```
  MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority
  MONGODB_DATABASE=security_scanner
  ```
- **Local:**
  ```bash
  docker run -d --name scanner-mongo -p 27017:27017 mongo:7
  ```
  ```
  MONGODB_URI=mongodb://localhost:27017
  MONGODB_DATABASE=security_scanner
  ```

On startup the backend creates its collections and indexes (`investigations`, `validation_attempts`).
It also marks attempts that a stopped backend left `RUNNING` as `ERROR`.

**Upgrading from the SQLite history:** an earlier version kept the history in `DB_PATH`.
To copy it into MongoDB, run the migration script. It never changes SQLite, never overwrites
existing MongoDB documents, and verifies every record. Re-running it is safe.
```bash
python scripts/migrate_validation_history.py --dry-run
python scripts/migrate_validation_history.py
```

### Tests

```bash
pip install -r requirements-dev.txt
TEST_MONGODB_URI=mongodb://localhost:27017 python -m pytest
```
The history tests need a real MongoDB server; each test uses its own throwaway database and drops it.
Without `TEST_MONGODB_URI` those tests are reported as skipped.

## 3. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Configure environment
cp .env.local.example .env.local
# Default API URL points to the Railway backend; override for local dev:
# NEXT_PUBLIC_API_URL=http://localhost:8000

# Start development server
npm run dev
```

The app will be available at `http://localhost:3000`.

## 4. Test with the Demo App

The `vulnerable-demo-app/` directory contains intentionally vulnerable Python and JavaScript code. It is also deployed as a separate GitHub repo for testing:

1. Visit the frontend (local or deployed)
2. Enter `https://github.com/3-rt/vulnerable-demo-app`
3. Click "Scan Repository"
4. Watch the progress tracker and review the results

## Deployment

### Backend (Railway)

1. Create a new service from your GitHub repo
2. Set **Root Directory** to `backend`
3. Railway detects the Dockerfile automatically
4. Add environment variables:
   - `MONGODB_URI`, `MONGODB_DATABASE` — validation history (allow Railway's egress in Atlas Network Access)
   - `GROQ_API_KEY` — Your Groq API key (optional)
5. The Dockerfile installs git, Semgrep (via pip), and Python dependencies

### Frontend (Vercel)

1. Import your GitHub repo on Vercel
2. Set **Root Directory** to `frontend`
3. Vercel auto-detects Next.js
4. The API URL defaults to the Railway backend via `next.config.mjs`

### Deploy Order

1. Deploy backend first to get the Railway URL
2. If needed, update the fallback URL in `frontend/lib/api.ts` and `frontend/next.config.mjs`
3. Deploy frontend on Vercel

## Environment Variables

### Backend (.env)

| Variable | Required | Default | Description |
|---|---|---|---|
| `GROQ_API_KEY` | No | — | Groq API key for AI explanations and AI fix suggestions |
| `GROQ_MODEL` | No | `openai/gpt-oss-120b` | Groq model |
| `MONGODB_URI` | For Validate Fix | — | MongoDB connection string for the validation history (never logged) |
| `MONGODB_DATABASE` | No | `security_scanner` | MongoDB database for the validation history |
| `MONGODB_TIMEOUT_MS` | No | `5000` | How long to wait for MongoDB before reporting it unreachable |
| `TEMP_DIR` | No | `/tmp/security_scans` | Temp directory for cloned repos |
| `MAX_REPO_SIZE_MB` | No | `500` | Max repo size limit |
| `SCAN_TIMEOUT_SECONDS` | No | `600` | Semgrep timeout |
| `DB_PATH` | No | `backend/data/scans.db` | SQLite file for scan results (the validation history is in MongoDB) |
| `FIX_MAX_ATTEMPTS` | No | `3` | Fix attempts per Validate Fix run (max 5) |
| `INVESTIGATION_MAX_ATTEMPTS` | No | `10` | Attempts per problem across all Validate Fix runs |
| `HISTORY_AVOID_AFTER_FAILURES` | No | `2` | Failures (with no pass) in comparable cases after which a predefined fix strategy is tried after the LLM |
| `VALIDATION_TEST_COMMAND` | No | — | Opt-in project test command run on the fixed copy (runs the scanned code on this host) |

### Frontend

| Variable | Required | Default | Description |
|---|---|---|---|
| `NEXT_PUBLIC_API_URL` | No | Railway URL (via `next.config.mjs`) | Backend API URL |

## Troubleshooting

**Semgrep not found**: Ensure `semgrep` is in your PATH. It is installed via `pip install semgrep` or as part of `requirements.txt`.

**CORS errors**: The backend allows all origins (`*`) by default for deployment flexibility.

**AI enhancement skipped**: If no `GROQ_API_KEY` is set, the scanner still works but provides generic explanations instead of AI-generated ones, and fix validation uses only the rule-based fixes.

**Validate Fix returns 503**: `MONGODB_URI` is missing, or MongoDB is unreachable. For Atlas, check the IP access list, the user and the password; the backend log says which (without the credentials).

**Scan timeout**: Large repositories may exceed the default 600-second timeout. Increase `SCAN_TIMEOUT_SECONDS` in `.env`.
