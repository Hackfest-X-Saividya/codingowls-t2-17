# System Overview — Building the AI Security Scanner from Scratch

This document explains what the system does, how its parts fit together, and the
order in which you would build it if starting from an empty folder.

---

## 1. What the system does

A user pastes a public GitHub repository URL. The system clones it, runs a static
security analysis, and returns a report where every finding has a plain-English
explanation, an attack scenario, a fixed code snippet, and a severity rating.

```
                                         ┌─▶ Semgrep scan ─▶ Parse SARIF ─┐
GitHub URL ─▶ Clone ─▶ Detect language ──┤                                ├─▶ Merge & dedupe ─▶ LLM verify/enhance ─▶ Report
                                         └─▶ ML detector (our model) ─────┘
```

Two independent detectors run in parallel: **Semgrep** (rule-based, precise on known
patterns) and **our own ML model** (learned, catches patterns no rule describes).
Their findings are merged, then the LLM verifies ML-only findings and writes the
explanations. The ML detector is **planned**; see [ML_MODEL_PLAN.md](ML_MODEL_PLAN.md).

## 2. Building blocks: built vs. reused

| Layer | Built in this project | Reused (third-party) |
|---|---|---|
| Web UI | Pages, components, polling flow | Next.js 14, React, Tailwind |
| API | Endpoints, scan state, progress tracking | FastAPI, Uvicorn, Pydantic |
| Clone | URL validation, size limit, cleanup | git, GitPython |
| Language detection | Extension counting + skip rules | — |
| Vulnerability detection (rules) | Ruleset selection per language | Semgrep engine + Semgrep Registry rules |
| Vulnerability detection (ML, planned) | Data pipeline, fine-tuned model, ONNX serving, merge logic | Pretrained code encoder (UniXcoder/CodeBERT), public vulnerability datasets |
| Result normalisation | SARIF → `Vulnerability`, severity mapping, critical escalation, snippet extraction | SARIF format (OASIS standard) |
| AI analysis | Prompt, JSON contract, concurrency + retry, fallback text | `openai/gpt-oss-120b` (open-weight) served by the Groq API |

Today detection is rule-based (Semgrep) and the LLM is called as a hosted API.
The planned ML detector adds a model we train ourselves and serve inside the backend.

## 3. Architecture

```
┌─────────────────────────────┐        ┌────────────────────────────────────────────────────────┐
│ Frontend (Next.js / Vercel) │        │ Backend (FastAPI / Railway, Docker)                     │
│                             │  HTTP  │                                                        │
│  ScanForm ── POST /api/scan ├───────▶│ routers/scan.py                                         │
│                             │◀───────┤   creates scan_id, launches background task             │
│  results/[scanId]           │        │                                                        │
│   ├─ poll GET .../status ───┼───────▶│   _run_scan():                                          │
│   └─ GET .../results ───────┼───────▶│     repo_manager → clone + detect language              │
│                             │        │            │                                           │
│  badges: Semgrep / ML / Both│        │            ├──────────────────────┐   (asyncio.gather) │
└─────────────────────────────┘        │            ▼                      ▼                    │
                                       │     semgrep_runner         function_extractor  *       │
                                       │            │                      │                    │
                                       │     sarif_parser           ml_detector (ONNX)  *       │
                                       │            └──────────┬───────────┘                    │
                                       │                       ▼                                │
                                       │              finding_merger  *                         │
                                       │                       ▼                                │
                                       │              ai_enhancer → Groq LLM                    │
                                       │   state kept in an in-memory dict                      │
                                       └────────────────────────────────────────────────────────┘
                                         * planned — see ML_MODEL_PLAN.md

Offline (not part of the request path):
  ml/  datasets ─▶ extract functions ─▶ clean/split ─▶ train ─▶ evaluate ─▶ export ONNX ─▶ model bundle
```

Key design choice: a scan takes 30s–several minutes, so `POST /api/scan` returns
immediately with a `scan_id` and the work runs as a background `asyncio` task.
The frontend polls the status endpoint every 2 seconds.

## 4. Project layout

```
ai-security-scanner/
├── backend/
│   ├── main.py                  # FastAPI app, CORS, /health
│   ├── routers/scan.py          # API endpoints + pipeline orchestration
│   ├── models/schemas.py        # Pydantic models, scan steps, progress weights
│   ├── services/
│   │   ├── repo_manager.py      # clone, language detection, cleanup
│   │   ├── semgrep_runner.py    # run Semgrep CLI → SARIF
│   │   ├── sarif_parser.py      # SARIF → Vulnerability objects
│   │   ├── function_extractor.py  # (planned) tree-sitter: repo → functions
│   │   ├── ml_detector.py       # (planned) ONNX model scoring
│   │   ├── finding_merger.py    # (planned) merge Semgrep + ML findings
│   │   └── ai_enhancer.py       # LLM enrichment via Groq
│   ├── utils/config.py          # env-driven settings
│   ├── Dockerfile, railway.toml
│   └── requirements.txt, .env.example
├── frontend/
│   ├── app/page.tsx             # landing page + scan form
│   ├── app/results/[scanId]/    # progress + report page
│   ├── components/              # ScanForm, ProgressTracker, VulnerabilityCard, CodeDiff, ...
│   └── lib/api.ts               # typed API client
├── ml/                          # (planned) data pipeline, training, evaluation, ONNX export
└── docs/
```

## 5. Build order

### Phase 1 — Backend skeleton
1. Create `backend/`, a virtualenv, and install `fastapi`, `uvicorn[standard]`,
   `pydantic`, `python-dotenv`.
2. `utils/config.py`: read every tunable from environment variables with defaults
   (`TEMP_DIR`, `MAX_REPO_SIZE_MB`, `SCAN_TIMEOUT_SECONDS`, `GROQ_API_KEY`, `GROQ_MODEL`).
   Call `.resolve()` on `TEMP_DIR` so it is an absolute, drive-qualified path.
3. `main.py`: create the app, add CORS, add `GET /health`.
4. Run `uvicorn main:app --reload --port 8000` and confirm `/health` responds.

### Phase 2 — Data contracts
Define everything in `models/schemas.py` before writing logic:
- `ScanRequest` with a validator that only accepts `https://github.com/<owner>/<repo>`
  (strip trailing `/` and `.git`).
- `ScanStatus` (`pending | running | complete | failed`) and `ScanStep`
  (`clone_repo → detect_language → analyze → parse_results → ai_enhance`).
- `STEP_WEIGHTS` so progress reflects real cost (Semgrep 35%, AI 40%).
- `Vulnerability`, `ScanSummary`, `ScanStatusResponse`, `ScanResultsResponse`.

The frontend's `lib/api.ts` interfaces mirror these exactly.

### Phase 3 — Repository handling (`repo_manager.py`)
- Shallow clone (`depth=1`, `single_branch=True`) into `TEMP_DIR/<scan_id>/repo`.
- Reject repos above `MAX_REPO_SIZE_MB`.
- Detect the primary language by counting file extensions, skipping `.git`,
  `node_modules`, `venv`, `dist`, `build`.
- `cleanup_scan()` deletes the scan folder; its `rmtree` error handler clears the
  read-only flag git sets on pack files (required on Windows).

### Phase 4 — Static analysis (`semgrep_runner.py`)
- Map language → Semgrep rulesets, e.g. Python → `p/python`, `p/flask`, `p/django`,
  `p/owasp-top-ten`; unknown → `p/owasp-top-ten`, `p/security-audit`.
- Run `semgrep scan --config ... --sarif --output results.sarif --metrics=off <repo>`.
- Treat exit codes `0` (clean) and `1` (findings) as success; anything else is an error.
- Run it via `asyncio.to_thread(subprocess.run, ...)` with a timeout and
  `PYTHONUTF8=1` in the environment (see §8).

### Phase 5 — Normalisation (`sarif_parser.py`)
- Index rules by ID from `runs[].tool.driver.rules`.
- For each result: map SARIF level (`error/warning/note`) → `high/medium/low`,
  escalate to `critical` if the rule or message matches injection /
  deserialization / path-traversal patterns.
- Make file paths repo-relative and pull a code snippet (±2 lines), refusing any
  path that resolves outside the repo.
- Always open files with `encoding="utf-8"`.

### Phase 5b — ML detector (planned)
Built in two halves; full detail in [ML_MODEL_PLAN.md](ML_MODEL_PLAN.md).
- **Offline (`ml/`)**: collect labeled vulnerable/safe functions (CVEfixes, CrossVul,
  VUDENC, ...), split by project, fine-tune a code encoder (UniXcoder/CodeBERT) to
  predict `p(vulnerable)` and a CWE class, evaluate against Semgrep, export to ONNX.
- **Online (backend)**: `function_extractor` splits the repo into functions,
  `ml_detector` scores them in batches, `finding_merger` combines the results with
  Semgrep's (same file + overlapping lines → one finding, `detected_by = ["semgrep", "ml"]`).
  Semgrep and the ML step run concurrently with `asyncio.gather`. The scan still works
  when the model is missing.

### Phase 6 — AI enhancement (`ai_enhancer.py`)
- One prompt per finding asking for strict JSON: `ai_explanation`,
  `attack_scenario`, `fixed_code`, `business_impact`, `fix_time_estimate`,
  `severity`, `confidence`, `false_positive_likelihood`.
- Call Groq's OpenAI-compatible endpoint
  (`https://api.groq.com/openai/v1/chat/completions`) with
  `response_format: {"type": "json_object"}` and low temperature.
- Run calls concurrently but bounded (`asyncio.Semaphore(4)`), retry on HTTP 429
  using `retry-after`.
- Parse defensively (strip code fences, extract the outermost `{...}`).
- If there is no API key or a call fails, fall back to rule-based explanations so
  the scan still completes.
- (Planned) For ML-only findings, the LLM first judges whether the function is really
  vulnerable. Rejected findings move to a "low confidence" section rather than being dropped.

### Phase 7 — Orchestration (`routers/scan.py`)
- `POST /api/scan`: create `scan_id`, store initial state, `asyncio.create_task(_run_scan(...))`.
- `_run_scan`: execute phases 3–6 in order, calling `_mark_step` / `_complete_step`
  to update progress; on exception set status `failed` with the error message;
  in `finally` always call `cleanup_scan`.
- `GET /api/scan/{id}/status` and `GET /api/scan/{id}/results` read the in-memory store.

### Phase 8 — Frontend
1. `npx create-next-app` (TypeScript, Tailwind, App Router).
2. `lib/api.ts`: `startScan`, `getScanStatus`, `getScanResults`; base URL from
   `NEXT_PUBLIC_API_URL` (fallback `http://localhost:8000`).
3. `ScanForm`: validate the URL client-side, call `startScan`, navigate to
   `/results/<scanId>`. Offer example vulnerable repos.
4. `results/[scanId]/page.tsx`: poll status every 2s → show `ProgressTracker`;
   on `complete` fetch results → `SummaryStats` + a `VulnerabilityCard` per finding
   (with `SeverityBadge` and `CodeDiff` for vulnerable vs. fixed code).

### Phase 9 — Deployment
- **Backend → Railway** with the Dockerfile: `python:3.12-slim`, install `git`,
  install Semgrep with `pipx` (isolated from the app's dependencies), then the app.
  `railway.toml` uses `/health` as the health check. Set `GROQ_API_KEY` as a
  Railway variable — never bake it into the image.
- **Frontend → Vercel** with `NEXT_PUBLIC_API_URL` set to the Railway URL.

## 6. API reference (summary)

| Method | Path | Returns |
|---|---|---|
| `POST` | `/api/scan` `{ "repo_url": "https://github.com/o/r" }` | `{ scan_id, status, message }` |
| `GET` | `/api/scan/{scan_id}/status` | `{ status, progress, current_step, steps_completed, steps_remaining, error }` |
| `GET` | `/api/scan/{scan_id}/results` | `{ repo_name, language, summary, vulnerabilities[] }` (202 while running) |
| `GET` | `/health` | Semgrep availability and version |

## 7. Configuration

| Variable | Where | Default | Purpose |
|---|---|---|---|
| `GROQ_API_KEY` | backend | — | Enables AI enhancement |
| `GROQ_MODEL` | backend | `openai/gpt-oss-120b` | LLM used for enhancement |
| `TEMP_DIR` | backend | `/tmp/security_scans` | Clones and SARIF output |
| `MAX_REPO_SIZE_MB` | backend | `500` | Reject larger repos |
| `SCAN_TIMEOUT_SECONDS` | backend | `600` | Semgrep timeout |
| `NEXT_PUBLIC_API_URL` | frontend | `http://localhost:8000` | Backend base URL |

## 8. Pitfalls learned the hard way

| Symptom | Cause | Fix |
|---|---|---|
| `TypeError: Router.__init__() got an unexpected keyword argument 'on_startup'` | Semgrep in the same venv pulled in Starlette 1.x, incompatible with FastAPI 0.115 | Pin `starlette<0.39`, or install Semgrep separately with `pipx` (as the Dockerfile does) |
| Frontend shows "Failed to fetch" | API URL pointed at a dead deployment; the 404 had no CORS headers | Read the URL from `NEXT_PUBLIC_API_URL` |
| `destination path ... already exists` on clone (Windows) | `/tmp/...` became `\tmp\...`, which git resolves differently from Python | `Path(...).resolve()` the temp dir |
| Scan fails with an empty error (Windows + `--reload`) | Selector event loop can't spawn asyncio subprocesses → `NotImplementedError` | Use `asyncio.to_thread(subprocess.run, ...)` |
| Semgrep exits with code 2, `'charmap' codec can't encode` | Semgrep writes SARIF in cp1252 on Windows | Run with `PYTHONUTF8=1`; read files as UTF-8 |
| Temp folders pile up | git pack files are read-only; `rmtree(ignore_errors=True)` silently skips them | `rmtree` error handler that `chmod`s and retries |

## 9. Known limitations / next steps

- **State is in memory:** restarts lose scans and multiple workers don't share it. Use Redis or a database.
- **No rate limiting:** a `slowapi` limiter is created but not applied. Add `@limiter.limit(...)` to `POST /api/scan` to protect the Groq quota.
- **Open CORS:** `allow_origins=["*"]` should become the frontend's domain in production.
- **One language per scan:** only the dominant language's rulesets run, so mixed repos get partial coverage.
- **Licensing:** Semgrep Registry rules are under the Semgrep Rules License, so check its terms before offering the scanner as a public service.
- **No tests yet:** add unit tests for `sarif_parser` and `detect_language`, plus an end-to-end scan against a known vulnerable repo.
