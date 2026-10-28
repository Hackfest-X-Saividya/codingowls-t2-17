# ML Vulnerability Detector — Implementation Plan

Goal: add our own trained model as a **second, independent detector** that runs
alongside Semgrep, so code is checked by both rule-based and learned analysis.

```
                    ┌─▶ Semgrep (rules) ──────────┐
Clone ─▶ Detect ────┤                             ├─▶ Merge & dedupe ─▶ LLM verify/enhance ─▶ Report
          language  └─▶ ML detector (our model) ──┘
```

> **Expectation setting:** no tool, or combination of tools, guarantees zero missed
> vulnerabilities. The point of two detectors is **higher recall**: Semgrep is precise
> on known patterns, and the model can catch issues no rule describes. The model will
> also produce false positives. The merge + LLM verification steps exist to keep
> those from flooding the report.

---

## 1. Problem definition

| Decision | Choice for v1 | Why |
|---|---|---|
| Unit of analysis | **Function / method** | Small enough for a transformer context window and specific enough to point at a location |
| Output | `p(vulnerable)` and a **CWE class** (top ~10 CWEs + "other") | The vulnerable/safe score drives filtering; the CWE gives the LLM and the user a category |
| Languages | **Python and JavaScript/TypeScript** first | Most-scanned languages in this app, with labeled data available in multi-language datasets. Add Java/PHP/Go in v2. |
| Line localisation | Function span in v1; token attribution in v2 | Function-level is reliable; line-level needs extra work |

Target CWEs for v1 (mapping to what users care about): CWE-89 SQLi, CWE-78 OS
command injection, CWE-79 XSS, CWE-22 path traversal, CWE-94 code injection,
CWE-502 unsafe deserialization, CWE-918 SSRF, CWE-798 hardcoded credentials,
CWE-327 weak crypto, CWE-611 XXE, plus `other`.

## 2. Data

### 2.1 Sources

**Real-world code only. No synthetic suites** (Juliet, SARD and OWASP Benchmark are excluded).

| Dataset | Role | Languages | What it gives us |
|---|---|---|---|
| **CVEfixes** | Primary training | Many (incl. Python, JS) | Real CVE fix commits → *before* = vulnerable, *after* = fixed; method-level, CWE labels. Collection tool can be re-run for newer CVEs. |
| **CrossVul** | Primary training | 40+ languages | Vulnerable/fixed **file** pairs from CVE commits with CWE labels. Run through our own function extractor; dedupe against CVEfixes. |
| **GitHub Advisory Database / OSV.dev** (self-mined) | Training + time-split test | Python (PyPI), JS/TS (npm) | Advisories linking to fix commits; mine them with the same before/after extraction. Source of the most recent data. |
| **VUDENC** | Supplementary training | Python | Real GitHub commits for SQLi, XSS, command injection, XSRF, RCE, path disclosure, open redirect. Labels are heuristic, so give them lower weight. |
| **SecBench.js** | **Evaluation only** | JavaScript (Node.js) | Real npm vulnerabilities with working exploits, so the labels are highly reliable. Never train on it. |
| **Negatives** | Training | Python, JS | (a) post-fix versions of vulnerable functions; (b) functions from well-maintained repos never touched by a security fix, deduped against positives |
| **Our own feedback** (later) | Training | Any | "Confirmed / false positive" clicks from the report UI |

Not used for v1: DiverseVul, Big-Vul, PrimeVul and MegaVul are real but almost entirely
C/C++. Revisit if C/C++ support is added.

**Split strategy:** train on CVEfixes, CrossVul and GHSA data up to a cutoff date.
Test on GHSA advisories published after the cutoff plus SecBench.js, so the model is
measured on vulnerabilities it could not have seen. Expect thousands (not hundreds of
thousands) of vulnerable Python/JS functions after dedup, which is why the
baseline-first approach matters.

All datasets must be checked for licence terms before use. Raw data stays out of git
(`ml/data/` is gitignored); download scripts are committed instead.

### 2.2 Processing pipeline (`ml/scripts/`)

1. **`download.py`**: fetch datasets into `ml/data/raw/`.
2. **`extract_functions.py`**: parse files with **tree-sitter** (Python + JS/TS
   grammars) and emit one record per function:
   `{repo, file, start_line, end_line, code, label, cwe, commit_date}`.
   - From fix commits: functions changed by the fix → *before* version = vulnerable,
     *after* version = safe.
   - Functions not changed by the fix are **not** automatically labeled safe (noisy).
3. **`clean.py`**:
   - Normalise whitespace and drop comments (so the model doesn't learn from comments like "fix CVE").
   - **Deduplicate** by normalised hash. Duplicate functions across splits inflate scores badly.
   - Drop trivially short functions (< 3 lines) and huge ones (> 400 lines).
4. **`split.py`**: split **by project** (and by time where possible), never randomly
   by function. Random splits leak project style into the test set and produce misleadingly high F1.
5. Output: `ml/data/processed/{train,val,test}.jsonl` plus a `stats.md` with class counts.

### 2.3 Class imbalance
Real code is overwhelmingly safe. Keep a realistic ratio in **val/test**
(e.g. 1 vulnerable : 10+ safe). In training, use class-weighted loss or
down-sample negatives. Never balance the test set, or the precision numbers will be
fiction.

## 3. Model

### 3.1 Architecture
- **Backbone:** a pretrained code encoder, **UniXcoder** or **CodeBERT** (~125M params).
  Start with UniXcoder, which generally does better on code understanding tasks.
- **Heads:** shared encoder → `[CLS]` →
  - binary head: vulnerable vs. safe (sigmoid)
  - CWE head: softmax over the target CWEs + `other` (loss applied to vulnerable samples only)
- **Input:** `<lang> <file path> <function code>`, truncated or windowed to 512 tokens.
  Long functions use overlapping windows; the function score is the max over windows.

### 3.2 Baseline first
Before fine-tuning, train a **TF-IDF + logistic regression / LightGBM** baseline on
the same splits. If the transformer doesn't clearly beat it on held-out projects,
investigate the data before adding complexity.

### 3.3 Training (`ml/train.py`)
- Hugging Face `transformers` + `datasets`. Defaults: lr 2e-5, batch 16–32,
  3–5 epochs, early stopping on val PR-AUC, seed fixed and logged.
- Hardware: a single T4/A10 GPU is enough (Colab, Kaggle, or a cloud VM). CPU-only
  training is not practical for the transformer; the baseline trains fine on a laptop.
- Track experiments (MLflow or Weights & Biases): config, data version, metrics, model hash.

### 3.4 Evaluation (`ml/eval.py`)

| Metric | Why |
|---|---|
| **PR-AUC**, precision/recall/F1 at chosen threshold | Accuracy is meaningless on imbalanced data |
| **Recall @ fixed precision** (e.g. precision ≥ 0.5) | Matches how we'll use it: catch more, but keep noise bounded |
| Per-CWE precision/recall | Find which classes the model can and can't handle |
| **Unique catches vs. Semgrep** | On test repos, how many true vulnerabilities did the model find that Semgrep missed? This is the number that justifies option B. |
| Inference latency per 1k functions (CPU) | Must fit the scan time budget |

**Threshold selection:** choose the operating threshold on the **validation** set,
then report on test once. Store the threshold with the model.

## 4. Serving inside the scanner

### 4.1 Model packaging
- Export to **ONNX** (`ml/export_onnx.py`), optionally with dynamic int8
  quantisation (~4× smaller, faster on CPU). The backend then needs only
  `onnxruntime` + `tokenizers`, not PyTorch.
- Artifact bundle: `model.onnx`, `tokenizer.json`, `labels.json`, `config.json`
  (threshold, max length, model version).
- Storage: Git LFS, or download from a release URL / object storage at container
  start (`ML_MODEL_URL`). Don't commit large binaries to plain git.

### 4.2 New backend modules

```
backend/services/
├── function_extractor.py   # tree-sitter: repo → list[CodeFunction(file, start, end, code, lang)]
├── ml_detector.py          # load ONNX once; batch-score functions → list[Vulnerability]
└── finding_merger.py       # merge Semgrep + ML results, dedupe, set detected_by
```

- `ml_detector.py`
  - Loaded lazily once per process (module-level singleton).
  - Scores in batches with `asyncio.to_thread`, so the event loop stays free.
  - Emits a `Vulnerability` for each function above threshold, with
    `rule_id = "ml/<cwe>"`, `title = "Possible <CWE name> (ML)"`, line = function start.
  - Budget guard: cap at `ML_MAX_FUNCTIONS` (e.g. 5,000). If exceeded, prioritise
    files with risky imports or names (`db`, `query`, `exec`, `upload`, routes/controllers)
    and record in the report that coverage was partial.
- `finding_merger.py`
  - Same file and overlapping line range → one finding, `detected_by = ["semgrep", "ml"]`.
    Agreement raises confidence.
  - ML-only findings are kept but flagged `detected_by = ["ml"]`.
- If the model files are missing or `ML_ENABLED=false`, skip the ML step and log it.
  Scans must still work without the model.

### 4.3 Pipeline changes (`routers/scan.py`)

```python
# after language detection
semgrep_task = semgrep_runner.run_scan(repo_path, language, scan_id)
ml_task = ml_detector.scan_repo(repo_path, language)
sarif_path, ml_findings = await asyncio.gather(semgrep_task, ml_task)

semgrep_findings = sarif_parser.parse_sarif(sarif_path, repo_path)
findings = finding_merger.merge(semgrep_findings, ml_findings)
enhanced = await ai_enhancer.enhance_vulnerabilities(findings)
```

- New steps in `ScanStep`: `ML_ANALYZE`, `MERGE` (and adjust `STEP_WEIGHTS`).
- **LLM verification for ML-only findings:** extend the prompt so that for
  `detected_by == ["ml"]` the LLM first judges whether the function is actually
  vulnerable. Findings it rejects with high `false_positive_likelihood` are moved to a
  collapsed "low confidence" section instead of being deleted, so nothing is silently dropped.

### 4.4 Schema / API changes
`models/schemas.py` → `Vulnerability` gains:

| Field | Type | Meaning |
|---|---|---|
| `detected_by` | `list[str]` | `["semgrep"]`, `["ml"]`, or both |
| `ml_score` | `float \| None` | Model's `p(vulnerable)` |
| `cwe` | `str \| None` | e.g. `"CWE-89"` |

`ScanResultsResponse` gains `ml_model_version` and `ml_coverage` (functions scanned / total).
Mirror all of this in `frontend/lib/api.ts`.

### 4.5 Frontend
- Source badges on `VulnerabilityCard`: **Semgrep**, **ML**, **Both**.
- Filter by source, and a "Show low-confidence ML findings" toggle.
- **Feedback buttons** ("Confirmed" / "False positive") → new `POST /api/feedback`
  stored server-side → future training data.

### 4.6 Config

| Variable | Default | Purpose |
|---|---|---|
| `ML_ENABLED` | `true` | Turn the ML step on/off |
| `ML_MODEL_DIR` | `./ml_model` | Where the ONNX bundle lives |
| `ML_MODEL_URL` | — | Optional download location at startup |
| `ML_THRESHOLD` | from `config.json` | Override the operating threshold |
| `ML_MAX_FUNCTIONS` | `5000` | Per-scan budget |

### 4.7 Deployment
- Dockerfile: add `onnxruntime`, `tokenizers`, `tree-sitter` + grammars; copy or
  download the model bundle.
- Expect +200–600 MB image size and +0.5–1.5 GB RAM depending on quantisation, so
  check the Railway plan limits. Alternative: run the model as a separate inference
  service (FastAPI + ONNX) that the backend calls over HTTP. This keeps the main API light.

## 5. Repository layout

```
ml/
├── README.md                # how to reproduce data + training
├── requirements.txt         # torch, transformers, datasets, tree-sitter, scikit-learn, ...
├── configs/unixcoder_v1.yaml
├── scripts/
│   ├── download.py
│   ├── extract_functions.py
│   ├── clean.py
│   └── split.py
├── baseline.py              # TF-IDF + LR/LightGBM
├── train.py
├── eval.py
├── export_onnx.py
├── notebooks/               # exploration only
└── data/                    # gitignored
```

The training stack (`torch`, etc.) never goes into `backend/requirements.txt`.

## 6. Milestones

| # | Milestone | Deliverable | Exit criteria |
|---|---|---|---|
| M1 | Data pipeline | `ml/scripts/*`, processed JSONL, `stats.md` | Project-level splits, dedup verified (no hash overlap between splits) |
| M2 | Baseline | `baseline.py` + metrics report | PR-AUC recorded on held-out projects |
| M3 | Transformer model | `train.py`, `eval.py`, checkpoint | Beats baseline on PR-AUC; per-CWE table |
| M4 | Semgrep comparison | Eval report on test repos | Count of true vulns found by ML but missed by Semgrep (> 0, documented) |
| M5 | Export + backend integration | ONNX bundle, `function_extractor.py`, `ml_detector.py`, `finding_merger.py`, schema changes | End-to-end scan shows Semgrep, ML and merged findings; scan works with ML disabled |
| M6 | LLM verification + UI | Prompt changes, source badges, filters | ML-only findings verified; low-confidence section in UI |
| M7 | Deploy + feedback loop | Docker/Railway changes, `POST /api/feedback` | Deployed; feedback stored; retraining procedure documented |

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| High false-positive rate (common for learned detectors on real-world code) | Conservative threshold, LLM verification, low-confidence section, feedback loop |
| Inflated offline metrics from data leakage | Dedup + project/time-based splits; evaluate on repos the model never saw |
| Noisy labels from fix commits (not every changed function was vulnerable) | Keep only functions directly changed by the fix; prefer curated subsets; manual spot-check of ~200 samples |
| Scan time grows on large repos | Batching, int8 quantisation, `ML_MAX_FUNCTIONS` budget with risk-based prioritisation |
| Memory limits on Railway | Quantised model, or separate inference service |
| Model trained on Python/JS only | Clearly report "ML coverage: not available for <language>" instead of silently skipping |

## 8. Definition of done (v1)

- ML detector runs on every Python/JS scan, in parallel with Semgrep.
- Each finding shows which detector(s) found it.
- On the held-out evaluation repos the combined system has higher recall than
  Semgrep alone, with precision reported honestly.
- The scanner still works when the model is absent.
- Training is reproducible from `ml/README.md`.
