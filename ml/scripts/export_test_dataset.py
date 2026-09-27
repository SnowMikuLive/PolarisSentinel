# 从 CIC 测试集导出 Charts 样本，不修改特征或标签。
# Export Charts samples from the CIC test split without changing features or labels.
import csv
import hashlib
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "prepared.npz"
OUTPUT = ROOT / "artifacts" / "cic_test_dataset.csv"
SEED = 42
PER_CLASS = 100


def main():
    with np.load(SOURCE, allow_pickle=False) as data:
        features = data["feature_names"].tolist()
        classes = data["class_names"].tolist()
        x = data["X_test"]
        y = data["y_test"]

    rng = np.random.default_rng(SEED)
    indices = []
    for label in range(len(classes)):
        candidates = np.flatnonzero(y == label)
        indices.extend(rng.choice(candidates, PER_CLASS, replace=False).tolist())
    rng.shuffle(indices)
    selected = x[indices]
    if selected.shape[1] != 20 or not np.isfinite(selected).all():
        raise ValueError("Expected 20 finite features per row.")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(features + ["label"])
        for index in indices:
            writer.writerow(x[index].tolist() + [classes[int(y[index])]])

    # 行号对应 X_test/y_test，便于核对真实来源。
    # Row indices refer to X_test/y_test for source verification.
    details = {
        "source": "ml/data/prepared.npz",
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "split": "test",
        "seed": SEED,
        "class_counts": {name: PER_CLASS for name in classes},
        "row_indices": indices,
        "note": "Real CIC-IDS2017 feature rows with existing grouped labels. "
                "Balanced sample for Charts checks, not full-test or live-traffic metrics. "
                "No synthetic jitter or prediction-based selection."
    }
    OUTPUT.with_suffix(".json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(f"Exported {len(indices)} rows to {OUTPUT}")
    print(details["class_counts"])


if __name__ == "__main__":
    main()
