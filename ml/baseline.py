"""Baseline: TF-IDF over code tokens + logistic regression (CPU, minutes).

The transformer in train.py has to beat this on held-out projects to be worth it.

Usage:
    python ml/baseline.py --data ml/data/processed --out ml/models/baseline
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from metrics import best_threshold, binary_report


def load(path: Path) -> tuple[list[str], np.ndarray]:
    rows = [json.loads(l) for l in path.open(encoding="utf-8")]
    return [f"<{r['lang']}> {r['code']}" for r in rows], np.array([r["label"] for r in rows])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path("ml/data/processed"))
    ap.add_argument("--out", type=Path, default=Path("ml/models/baseline"))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    x_train, y_train = load(args.data / "train.jsonl")
    x_val, y_val = load(args.data / "val.jsonl")
    x_test, y_test = load(args.data / "test.jsonl")
    print(f"train={len(y_train)} val={len(y_val)} test={len(y_test)}")

    vec = TfidfVectorizer(
        token_pattern=r"[A-Za-z_][A-Za-z0-9_]*|[^\sA-Za-z0-9_]",
        ngram_range=(1, 2), min_df=2, max_features=300_000, sublinear_tf=True,
    )
    clf = LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0)
    clf.fit(vec.fit_transform(x_train), y_train)

    p_val = clf.predict_proba(vec.transform(x_val))[:, 1]
    p_test = clf.predict_proba(vec.transform(x_test))[:, 1]
    threshold = best_threshold(y_val, p_val)
    report = {
        "threshold": threshold,
        "val": binary_report(y_val, p_val, threshold),
        "test": binary_report(y_test, p_test, threshold),
    }
    print(json.dumps(report, indent=2))

    joblib.dump({"vectorizer": vec, "classifier": clf, "threshold": threshold}, args.out / "baseline.joblib")
    (args.out / "metrics.json").write_text(json.dumps(report, indent=2))
    print(f"Saved to {args.out}")


if __name__ == "__main__":
    main()
