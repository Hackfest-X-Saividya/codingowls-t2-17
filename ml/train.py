"""Fine-tune a code encoder (default: microsoft/unixcoder-base) to detect
vulnerable functions and classify their CWE.

Model: encoder -> [CLS] -> (a) vulnerable/fixed logit, (b) CWE logits.
The CWE loss only applies to vulnerable samples.

Defaults are sized for a 4 GB GPU (fp16, batch 4, grad-accumulation 8,
gradient checkpointing). Early-stops on validation PR-AUC, then evaluates
the best checkpoint on the test split once.

Usage:
    python ml/train.py --data ml/data/processed --out ml/models/unixcoder_v1
"""
from __future__ import annotations

import argparse
import json
import math
import random
import time
from pathlib import Path

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModel, AutoTokenizer, get_linear_schedule_with_warmup

from metrics import best_threshold, binary_report


class FunctionDataset(Dataset):
    def __init__(self, path: Path, cwe_index: dict[str, int]):
        self.rows = [json.loads(l) for l in path.open(encoding="utf-8")]
        self.cwe_index = cwe_index

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, i: int) -> dict:
        r = self.rows[i]
        return {
            "text": f"<{r['lang']}> {r['path']}\n{r['code']}",
            "label": float(r["label"]),
            "cwe": self.cwe_index.get(r["cwe"], self.cwe_index["other"]),
        }


class VulnDetector(nn.Module):
    def __init__(self, encoder_name: str, num_cwes: int):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(encoder_name)
        hidden = self.encoder.config.hidden_size
        self.dropout = nn.Dropout(0.1)
        self.vuln_head = nn.Linear(hidden, 1)
        self.cwe_head = nn.Linear(hidden, num_cwes)

    def forward(self, input_ids, attention_mask):
        cls = self.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state[:, 0]
        cls = self.dropout(cls)
        return self.vuln_head(cls).squeeze(-1), self.cwe_head(cls)


def make_collate(tokenizer, max_len: int):
    def collate(batch: list[dict]) -> dict:
        enc = tokenizer([b["text"] for b in batch], truncation=True, max_length=max_len,
                        padding=True, return_tensors="pt")
        enc["label"] = torch.tensor([b["label"] for b in batch])
        enc["cwe"] = torch.tensor([b["cwe"] for b in batch])
        return enc
    return collate


@torch.no_grad()
def predict(model, loader, device) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    model.eval()
    probs, labels, cwe_pred, cwe_true = [], [], [], []
    for batch in loader:
        with torch.autocast(device_type=device.type, enabled=device.type == "cuda"):
            vuln_logit, cwe_logit = model(batch["input_ids"].to(device), batch["attention_mask"].to(device))
        probs.append(torch.sigmoid(vuln_logit.float()).cpu().numpy())
        labels.append(batch["label"].numpy())
        cwe_pred.append(cwe_logit.argmax(-1).cpu().numpy())
        cwe_true.append(batch["cwe"].numpy())
    model.train()
    return (np.concatenate(probs), np.concatenate(labels).astype(int),
            np.concatenate(cwe_pred), np.concatenate(cwe_true))


def cwe_accuracy(y: np.ndarray, pred: np.ndarray, true: np.ndarray) -> float:
    mask = y == 1
    return round(float((pred[mask] == true[mask]).mean()), 4) if mask.any() else float("nan")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path("ml/data/processed"))
    ap.add_argument("--out", type=Path, default=Path("ml/models/unixcoder_v1"))
    ap.add_argument("--model", default="microsoft/unixcoder-base")
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--batch-size", type=int, default=4)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--epochs", type=int, default=5)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--cwe-weight", type=float, default=0.5)
    ap.add_argument("--patience", type=int, default=2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--no-grad-checkpointing", action="store_true")
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    args.out.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}" + (f" ({torch.cuda.get_device_name(0)})" if device.type == "cuda" else
                                  "  -- WARNING: no CUDA, training will be very slow"))

    classes = json.loads((args.data / "labels.json").read_text())["cwe_classes"]
    cwe_index = {c: i for i, c in enumerate(classes)}
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    collate = make_collate(tokenizer, args.max_len)
    train_ds = FunctionDataset(args.data / "train.jsonl", cwe_index)
    val_ds = FunctionDataset(args.data / "val.jsonl", cwe_index)
    test_ds = FunctionDataset(args.data / "test.jsonl", cwe_index)
    print(f"train={len(train_ds)} val={len(val_ds)} test={len(test_ds)} cwe_classes={len(classes)}")

    train_dl = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, collate_fn=collate)
    val_dl = DataLoader(val_ds, batch_size=args.batch_size * 4, collate_fn=collate)
    test_dl = DataLoader(test_ds, batch_size=args.batch_size * 4, collate_fn=collate)

    model = VulnDetector(args.model, len(classes)).to(device)
    if not args.no_grad_checkpointing:
        model.encoder.gradient_checkpointing_enable()

    labels = np.array([r["label"] for r in train_ds.rows])
    pos_weight = torch.tensor((labels == 0).sum() / max((labels == 1).sum(), 1), device=device)
    bce = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    ce = nn.CrossEntropyLoss()

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    total_steps = math.ceil(len(train_dl) / args.grad_accum) * args.epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, int(0.06 * total_steps), total_steps)
    scaler = torch.cuda.amp.GradScaler(enabled=device.type == "cuda")

    best_auc, bad_epochs, history = -1.0, 0, []
    for epoch in range(1, args.epochs + 1):
        started, running = time.time(), 0.0
        for step, batch in enumerate(train_dl, 1):
            with torch.autocast(device_type=device.type, enabled=device.type == "cuda"):
                vuln_logit, cwe_logit = model(batch["input_ids"].to(device), batch["attention_mask"].to(device))
                y = batch["label"].to(device)
                loss = bce(vuln_logit.float(), y)
                pos = y == 1
                if pos.any():
                    loss = loss + args.cwe_weight * ce(cwe_logit[pos].float(), batch["cwe"].to(device)[pos])
            scaler.scale(loss / args.grad_accum).backward()
            running += loss.item()
            if step % args.grad_accum == 0 or step == len(train_dl):
                scaler.unscale_(optimizer)
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad(set_to_none=True)
                scheduler.step()
            if step % 200 == 0:
                print(f"epoch {epoch} step {step}/{len(train_dl)} loss {running / step:.4f} "
                      f"({time.time() - started:.0f}s)")

        p, y, cp, ct = predict(model, val_dl, device)
        thr = best_threshold(y, p)
        val = binary_report(y, p, thr) | {"cwe_acc": cwe_accuracy(y, cp, ct), "threshold": thr}
        history.append({"epoch": epoch, "train_loss": running / len(train_dl), "val": val})
        print(f"epoch {epoch} val: {val}")

        if val["pr_auc"] > best_auc:
            best_auc, bad_epochs = val["pr_auc"], 0
            torch.save(model.state_dict(), args.out / "model.pt")
            print(f"  new best (PR-AUC {best_auc}) -> saved")
        else:
            bad_epochs += 1
            if bad_epochs >= args.patience:
                print("Early stopping.")
                break

    # Final: best checkpoint, threshold from validation, evaluated on test once
    model.load_state_dict(torch.load(args.out / "model.pt", map_location=device))
    p, y, _, _ = predict(model, val_dl, device)
    threshold = best_threshold(y, p)
    p, y, cp, ct = predict(model, test_dl, device)
    test = binary_report(y, p, threshold) | {"cwe_acc": cwe_accuracy(y, cp, ct)}
    print(f"TEST: {test}")

    tokenizer.save_pretrained(args.out / "tokenizer")
    (args.out / "config.json").write_text(json.dumps({
        "base_model": args.model, "max_len": args.max_len, "threshold": threshold,
        "cwe_classes": classes, "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "args": {k: str(v) for k, v in vars(args).items()},
    }, indent=2))
    (args.out / "metrics.json").write_text(json.dumps({"history": history, "test": test}, indent=2))
    print(f"Saved model + metrics to {args.out}")


if __name__ == "__main__":
    main()
