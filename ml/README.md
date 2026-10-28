# ML vulnerability detector — training

Trains our own model to flag vulnerable Python / JavaScript / TypeScript
functions. See [../docs/ML_MODEL_PLAN.md](../docs/ML_MODEL_PLAN.md) for the design.

Data: **CVEfixes v1.0.7** (real CVE fix commits; CC BY 4.0). For every function
a security fix changed: the version before the fix = vulnerable (1), after = fixed (0).

All commands run from the repo root (`ai-security-scanner/`) in PowerShell.

## 1. Environment (once)

```powershell
python -m venv ml\.venv
ml\.venv\Scripts\python.exe -m pip install --upgrade pip
# PyTorch with CUDA (NVIDIA GPU). For CPU-only drop the --index-url part.
ml\.venv\Scripts\python.exe -m pip install torch --index-url https://download.pytorch.org/whl/cu124
ml\.venv\Scripts\python.exe -m pip install -r ml\requirements.txt
ml\.venv\Scripts\python.exe -c "import torch; print(torch.__version__, torch.cuda.is_available())"
```

The last line must print `True` to train on the GPU.

## 2. Data

```powershell
# Download (3.9 GB). --ssl-no-revoke works around Windows' revocation-check failure.
curl.exe --ssl-no-revoke -L -C - -o datasets\raw\CVEfixes_v1.0.7.zip "https://zenodo.org/api/records/7029359/files/CVEfixes_v1.0.7.zip/content"

# Extract Python/JS/TS functions (streams the dump from the zip; ~20–40 min)
ml\.venv\Scripts\python.exe ml\scripts\prepare_cvefixes.py --zip datasets\raw\CVEfixes_v1.0.7.zip --out ml\data\interim\functions.jsonl

# Clean, dedupe, split by repository -> train/val/test.jsonl, labels.json, stats.md
ml\.venv\Scripts\python.exe ml\scripts\build_splits.py --inp ml\data\interim\functions.jsonl --out ml\data\processed
```

## 3. Train

```powershell
# Baseline (CPU, minutes) — the number to beat
ml\.venv\Scripts\python.exe ml\baseline.py --data ml\data\processed --out ml\models\baseline

# Main model: UniXcoder fine-tune (GPU, hours). Defaults fit a 4 GB GPU.
ml\.venv\Scripts\python.exe ml\train.py --data ml\data\processed --out ml\models\unixcoder_v1
```

If you hit `CUDA out of memory`: add `--max-len 384` or `--batch-size 2 --grad-accum 16`.

Outputs in `ml\models\unixcoder_v1\`: `model.pt`, `tokenizer\`, `config.json`
(threshold chosen on validation, CWE classes), `metrics.json` (per-epoch
validation + final test).

## Reading the results

- **PR-AUC** is the main metric; compare the model's test PR-AUC with the baseline's.
- The test set is roughly balanced (vulnerable vs. fixed versions of the same
  functions), and **real code is mostly safe**. So the precision measured here is
  higher than what you'll see in real scans.
- Telling a function apart from its own fixed version is a hard task. Published
  results on CVEfixes-style data are modest, so don't expect 90%+ F1.
