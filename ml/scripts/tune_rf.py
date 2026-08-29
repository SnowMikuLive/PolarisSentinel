import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
METRICS_PATH = ROOT / "artifacts" / "metrics_tuning.json"
SEED = 42
BENIGN = 0
THRESHOLDS = [0.50, 0.60, 0.70, 0.80, 0.90]

CONFIGS = [
    ("leaf5_baseline", {"min_samples_leaf": 5}, None),
    ("leaf1", {"min_samples_leaf": 1}, None),
    ("leaf1_balanced", {"min_samples_leaf": 1, "class_weight": "balanced"}, None),
    ("leaf1_down500k", {"min_samples_leaf": 1}, 500_000),
]


def summarize(y_true: np.ndarray, y_pred: np.ndarray, class_names: list[str]) -> dict:
    benign_mask = y_true == BENIGN
    out = {"benign_fpr": float((y_pred[benign_mask] != BENIGN).mean())}
    for idx, name in enumerate(class_names):
        if idx == BENIGN:
            continue
        mask = y_true == idx
        out[f"{name}_recall"] = float((y_pred[mask] == idx).mean())
    return out


def fmt(row: dict) -> str:
    return (f"FPR {row['benign_fpr']:.4%} | "
            + ", ".join(f"{k.removesuffix('_recall')} {v:.2%}"
                        for k, v in row.items() if k.endswith("_recall")))


def main() -> None:
    data = np.load(DATA_PATH)
    X_train, y_train = data["X_train"], data["y_train"]
    X_val, y_val = data["X_val"], data["y_val"]
    class_names = data["class_names"].tolist()

    results = []
    for name, params, benign_cap in CONFIGS:
        X_fit, y_fit = X_train, y_train
        if benign_cap is not None:
            rng = np.random.default_rng(SEED)
            benign_idx = np.flatnonzero(y_train == BENIGN)
            keep = rng.choice(benign_idx, size=benign_cap, replace=False)
            idx = np.sort(np.concatenate([keep, np.flatnonzero(y_train != BENIGN)]))
            X_fit, y_fit = X_train[idx], y_train[idx]

        model = RandomForestClassifier(
            n_estimators=100, n_jobs=-1, random_state=SEED, **params
        )
        start = time.perf_counter()
        model.fit(X_fit, y_fit)
        fit_seconds = time.perf_counter() - start

        proba = model.predict_proba(X_val)
        y_pred = np.argmax(proba, axis=1)
        confidence = proba.max(axis=1)

        entry = {
            "config": name,
            "params": {**params, "benign_cap": benign_cap},
            "fit_seconds": round(fit_seconds, 1),
            "train_rows": int(len(y_fit)),
            "argmax": summarize(y_val, y_pred, class_names),
            "thresholds": {},
        }
        print(f"\n=== {name} (fit {fit_seconds:.0f}s, {len(y_fit):,} rows) ===")
        print(f"    argmax          {fmt(entry['argmax'])}")

        # policy view: attack prediction below the confidence threshold is not acted on
        for t in THRESHOLDS:
            gated = np.where((y_pred != BENIGN) & (confidence < t), BENIGN, y_pred)
            row = summarize(y_val, gated, class_names)
            entry["thresholds"][f"{t:.2f}"] = row
            print(f"    conf >= {t:.2f}    {fmt(row)}")

        results.append(entry)

    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(
        json.dumps({"seed": SEED, "val_rows": int(len(y_val)), "results": results}, indent=2),
        encoding="utf-8",
    )
    print(f"\nSaved {METRICS_PATH}")


if __name__ == "__main__":
    main()
