# AI Security Scanner

Official HackFest 2026 repository for team **CodingOwls (T2-17)**.

Paste a public GitHub repository URL and get a readable security report. The scanner
checks the **code**, the **dependencies** and **hardcoded secrets**, then uses an LLM to
explain each finding in plain English, with an attack scenario, a suggested fix and a
severity rating. Results export as **SARIF** (for GitHub code scanning) or **PDF**, and a
command-line version can run in CI to block risky pull requests.

## Features

- **Static code analysis**: Semgrep rules selected per detected language, including OWASP checks
- **Dependency check**: pinned package versions matched against the [OSV.dev](https://osv.dev) database
- **Secret detection**: API keys, tokens, private keys and passwords committed to the repo
- **AI explanations**: findings enriched in parallel by an LLM (`openai/gpt-oss-120b` via Groq)
- **Live progress**: per-step progress tracker while the scan runs
- **Exports**: SARIF 2.1.0 and PDF reports, plus scan history
- **CLI**: scan a local folder and fail the build at a chosen severity
- **ML detector (in progress)**: our own fine-tuned UniXcoder model for vulnerable functions (see [ml/](ml/README.md))

## How it works

```
GitHub URL ─▶ Clone (depth=1) ─▶ Detect languages ─┬─▶ Code analysis ─▶ Parse SARIF ─┐
                                                   ├─▶ Dependency check (OSV) ───────┼─▶ AI enhance (parallel) ─▶ Report
                                                   └─▶ Secret scan ──────────────────┘
```

`POST /api/scan` returns immediately with a `scan_id`. The scan runs as a background task
and the frontend polls its status until the report is ready.

## Tech stack

| Part | Stack |
|---|---|
| Frontend | Next.js 14, React, TypeScript, Tailwind CSS |
| Backend | FastAPI, Uvicorn, Pydantic, GitPython, SQLite (scan history) |
| Analysis | Semgrep, OSV.dev API, custom secret scanner |
| AI | Groq API (`openai/gpt-oss-120b`) |
| ML | PyTorch, Hugging Face Transformers (UniXcoder), scikit-learn baseline |
| Deploy | Vercel (frontend), Railway / Docker (backend) |

## Project layout

```
ai-security-scanner/
├── backend/            FastAPI app, scan pipeline, CLI (cli.py), Dockerfile
│   ├── routers/        API endpoints
│   ├── services/       repo_manager, semgrep_runner, sarif_parser, dependency_scanner,
│   │                   secret_scanner, ai_enhancer, sarif_export, pdf_report, scan_store
│   └── utils/config.py environment settings
├── frontend/           Next.js app (landing page, results page, components)
├── ml/                 dataset preparation, baseline and UniXcoder training
└── docs/               API, architecture, setup and ML plan
```

## Getting started

**Prerequisites:** Python 3.11+, Node.js 18+, Git, and Semgrep (`pip install semgrep`).
A [Groq API key](https://console.groq.com) is optional; without it, findings get generic explanations.

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate            # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env             # then set GROQ_API_KEY
uvicorn main:app --reload --port 8000
```

| Variable | Default | Purpose |
|---|---|---|
| `GROQ_API_KEY` | (empty) | Enables AI explanations |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | LLM used for explanations |
| `TEMP_DIR` | `/tmp/security_scans` | Where repositories are cloned |
| `MAX_REPO_SIZE_MB` | `500` | Larger repositories are rejected |
| `SCAN_TIMEOUT_SECONDS` | `600` | Per-scan time limit |
| `DB_PATH` | `backend/data/scans.db` | Scan history database |

### Frontend

```bash
cd frontend
npm install
cp .env.local.example .env.local   # NEXT_PUBLIC_API_URL=http://localhost:8000
npm run dev
```

Open http://localhost:3000.

## API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Start a scan: `{"repo_url": "https://github.com/owner/repo"}` |
| `GET` | `/api/scan/{id}/status` | Progress and current step |
| `GET` | `/api/scan/{id}/results` | Findings and summary |
| `GET` | `/api/scan/{id}/sarif` | SARIF 2.1.0 download |
| `GET` | `/api/scan/{id}/pdf` | PDF report download |
| `GET` | `/api/scans` | Recent scans |
| `GET` | `/health` | Health check |

More detail in [docs/API.md](docs/API.md).

## CLI

```bash
cd backend
python cli.py scan <path> --sarif results.sarif --pdf report.pdf --fail-on high
```

Options: `--json <file>`, `--no-ai` (skip the LLM), `--fail-on none|low|medium|high|critical`, `-v`.

The command exits with a non-zero code when findings at or above `--fail-on` exist, so it
can be added to any CI pipeline to block risky changes.

## ML model

The `ml/` folder trains a model that flags vulnerable Python / JavaScript / TypeScript
functions, using the CVEfixes dataset. See [ml/README.md](ml/README.md) for the full pipeline.

Current results on the test set:

| Model | PR-AUC | ROC-AUC |
|---|---|---|
| Baseline (TF-IDF + logistic regression) | 0.580 | 0.565 |
| UniXcoder v1 (fine-tuned) | 0.541 | 0.526 |

The fine-tuned model does not beat the baseline yet, so it is not used in scans. Improving
the training data is the next step.

## Documentation

- [docs/SETUP.md](docs/SETUP.md): detailed setup and deployment
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): system design
- [docs/API.md](docs/API.md): API reference
- [docs/ML_MODEL_PLAN.md](docs/ML_MODEL_PLAN.md): ML detector design
- [SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md): how the system is built, step by step
