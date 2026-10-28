# Setup Guide

## Live Demo

- **Frontend**: Hosted on Vercel
- **Backend**: Hosted on Railway

## Prerequisites (Local Development)

- **Python 3.11+** — Backend runtime
- **Node.js 18+** — Frontend runtime
- **Semgrep** — Static analysis engine (installed via pip)
- **Git** — For cloning target repositories
- **Anthropic API Key** (optional) — For AI-enhanced explanations

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
# Edit .env and set your ANTHROPIC_API_KEY (optional but recommended)

# Start the server
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.

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
   - `ANTHROPIC_API_KEY` — Your Claude API key
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
| `ANTHROPIC_API_KEY` | No | — | Claude API key for AI enhancement |
| `TEMP_DIR` | No | `/tmp/security_scans` | Temp directory for cloned repos |
| `MAX_REPO_SIZE_MB` | No | `500` | Max repo size limit |
| `SCAN_TIMEOUT_SECONDS` | No | `600` | Semgrep timeout |

### Frontend

| Variable | Required | Default | Description |
|---|---|---|---|
| `NEXT_PUBLIC_API_URL` | No | Railway URL (via `next.config.mjs`) | Backend API URL |

## Troubleshooting

**Semgrep not found**: Ensure `semgrep` is in your PATH. It is installed via `pip install semgrep` or as part of `requirements.txt`.

**CORS errors**: The backend allows all origins (`*`) by default for deployment flexibility.

**AI enhancement skipped**: If no `ANTHROPIC_API_KEY` is set, the scanner still works but provides generic explanations instead of AI-generated ones.

**Scan timeout**: Large repositories may exceed the default 600-second timeout. Increase `SCAN_TIMEOUT_SECONDS` in `.env`.
