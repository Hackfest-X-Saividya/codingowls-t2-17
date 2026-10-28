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
- **Attack chains**: data-flow analysis connects inputs, missing checks, weak auth and findings into evidence-backed chains, prioritised by exploitability (Python)
- **Fix validation**: chain-aware fixes are applied in a sandbox copy and re-checked for open paths, alternative paths, regressions and new issues, with bounded retries (see [docs/CHAIN_ANALYSIS.md](docs/CHAIN_ANALYSIS.md))
- **AI explanations**: findings enriched in parallel by an LLM (`openai/gpt-oss-120b` via Groq)
- **Live progress**: per-step progress tracker while the scan runs
- **Exports**: SARIF 2.1.0 and PDF reports, plus scan history
- **CLI**: scan a local folder and fail the build at a chosen severity
- **VS Code extension**: findings sidebar, squiggles and one-click fixes inside the editor (see [vscode-extension/](vscode-extension/README.md))
- **ML detector (in progress)**: our own fine-tuned UniXcoder model for vulnerable functions (see [ml/](ml/README.md))

## How it works

```
GitHub URL ─▶ Clone (depth=1) ─▶ Detect languages ─┬─▶ Code analysis ─▶ Parse SARIF ─┐
                                                   ├─▶ Dependency check (OSV) ───────┼─▶ Attack chains ─▶ AI enhance ─▶ Report
                                                   └─▶ Secret scan ──────────────────┘
Report ─▶ Validate a chain's fix: sandbox copy ─▶ re-check paths, scanner, regressions ─▶ retry with evidence
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
│   │                   secret_scanner, ai_enhancer, sarif_export, pdf_report, scan_store,
│   │                   flow_analyzer, chain_analysis, fix_planner, fix_validation
│   ├── tests/          pytest suite with fixture apps
│   └── utils/          config.py (environment settings), sandbox.py (validation isolation)
├── frontend/           Next.js app (landing page, results page, components)
├── ml/                 dataset preparation, baseline and UniXcoder training
├── vscode-extension/   VS Code extension (findings sidebar, quick fixes)
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
| `FIX_MAX_ATTEMPTS` | `3` | Fix attempts per validation (max 5); the loop also stops early when progress stalls |
| `VALIDATION_TEST_COMMAND` | (empty) | Opt-in project test command run in the sandbox, e.g. `python -m pytest -q`. Runs the scanned code on this host. |
| `VALIDATION_TEST_TIMEOUT` | `300` | Seconds per test run |
| `VALIDATION_KEEP_WORKSPACE` | (empty) | Set to `1` to keep sandbox copies for debugging |

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
| `GET` | `/api/scan/{id}/results` | Findings, summary, attack chains and validations |
| `POST` | `/api/scan/{id}/findings/{finding_id}/validate` | Validate the fix for any finding (code, dependency, secret) |
| `POST` | `/api/scan/{id}/chains/{chain_id}/validate` | Validate a chain's fix, or `{"edits": [...]}` for your own |
| `GET` | `/api/scan/{id}/validations/{validation_id}` | Validation status, attempts and evidence |
| `GET` | `/api/validation-stats` | Success rate per attempt, and whether a higher attempt limit would help |
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

To check a fix you made locally, compare a copy of the code before the fix with the fixed tree:

```bash
python cli.py validate ../app-before ../app-after   # PASS / FAIL / NEW_VULNERABILITY / INCONCLUSIVE per chain
```

## Tests

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest
```

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
- [docs/CHAIN_ANALYSIS.md](docs/CHAIN_ANALYSIS.md): attack chains, fix validation, limitations
- [docs/ML_MODEL_PLAN.md](docs/ML_MODEL_PLAN.md): ML detector design
- [SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md): how the system is built, step by step
