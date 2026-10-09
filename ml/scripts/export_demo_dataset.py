# 挑选真实 CIC 样本用于演示，不作为独立性能测试。
# Select real CIC examples for demonstration, not independent evaluation.
import csv
import hashlib
import json
from pathlib import Path
import numpy as np
import onnxruntime as ort

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "artifacts" / "cic_demo_dataset.csv"
SEED = 42
CLASS_COUNTS = {"Benign": 1200, "DoS": 750, "PortScan": 25, "BruteForce": 25}

def main():
    rf_path = ROOT / "artifacts" / "rf_model.onnx"
    if_path = ROOT / "artifacts" / "if_model.onnx"
    rf = ort.InferenceSession(str(rf_path))
    detector = ort.InferenceSession(str(if_path))
    rf_meta = rf.get_modelmeta().custom_metadata_map
    if_meta = detector.get_modelmeta().custom_metadata_map
    features = json.loads(rf_meta["feature_names"])
    rf_classes = json.loads(rf_meta["class_names"])
    rf_threshold = float(rf_meta["rf_confidence_threshold"])
    threshold = float(if_meta["anomaly_threshold"])
    rng = np.random.default_rng(SEED)

    with np.load(ROOT / "data" / "prepared.npz", allow_pickle=False) as data:
        x_test, y_test = data["X_test"], data["y_test"]
        classes = data["class_names"].tolist()
        assert features == data["feature_names"].tolist()
    assert features == json.loads(if_meta["feature_names"])

    rows = []
    for label, count in CLASS_COUNTS.items():
        indices = np.flatnonzero(y_test == classes.index(label))
        if label == "Benign":
            indices = rng.choice(indices, 5000, replace=False)

        matches = []
        rf_matches = []
        for start in range(0, len(indices), 4096):
            batch_indices = indices[start:start + 4096]
            batch = x_test[batch_indices]
            probabilities = rf.run(["probabilities"], {rf.get_inputs()[0].name: batch})[0]
            scores = detector.run(["scores"], {detector.get_inputs()[0].name: batch})[0].ravel()
            correct_rf = probabilities.argmax(axis=1) == rf_classes.index(label)
            if_attack = scores.astype(np.float64) < threshold
            match = correct_rf & ~if_attack if label == "Benign" else correct_rf & if_attack
            matches.extend(batch_indices[match].tolist())
            rf_matches.extend(batch_indices[correct_rf & (probabilities.max(axis=1) >= rf_threshold)].tolist())

        selected_count = count if label == "Benign" else int(count * 0.95)
        selected = rng.choice(matches, min(selected_count, len(matches)), replace=False)
        rf_pool = np.setdiff1d(rf_matches, selected)
        rf_selected = rng.choice(rf_pool, selected_count - len(selected), replace=False)
        remaining = np.setdiff1d(indices, np.concatenate([selected, rf_selected]))
        random_rows = rng.choice(remaining, count - selected_count, replace=False)
        for index in selected:
            rows.append((x_test[index], label, "test", int(index), "both_models"))
        for index in rf_selected:
            rows.append((x_test[index], label, "test", int(index), "rf_only"))
        for index in random_rows:
            rows.append((x_test[index], label, "test", int(index), "random"))
        print(f"{label}: {len(selected)} both models + {len(rf_selected)} RF only + {len(random_rows)} random", flush=True)

    rng.shuffle(rows)
    assert len(rows) == 2000 and np.isfinite(np.array([row[0] for row in rows])).all()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(features + ["label"])
        for values, label, _, _, _ in rows:
            writer.writerow(values.tolist() + [label])

    source = ROOT / "data" / "prepared.npz"
    details = {
        "purpose": "Curated demonstration only; not an independent performance test.",
        "scope": "Benign, DoS, PortScan and BruteForce only, following the proposal. DDoS excluded.",
        "source": "ml/data/prepared.npz",
        "split": "test",
        "selection": "Benign rows classified normal by both models. Attack rows: 95% selected (rounded down per class), preferring correct RF classifications also flagged by IF; use correct RF-only examples when IF misses the class. Remaining rows are randomly sampled.",
        "distribution_note": "DoS-focused demonstration with PortScan and BruteForce examples. This distribution does not represent overall attack traffic.",
        "seed": SEED,
        "class_counts": CLASS_COUNTS,
        "source_sha256": {"test": hashlib.sha256(source.read_bytes()).hexdigest()},
        "model_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (rf_path, if_path)},
        "if_threshold": threshold,
        "row_sources": [[source, index, selection] for _, _, source, index, selection in rows],
    }
    OUTPUT.with_suffix(".json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(f"Exported {len(rows)} demonstration rows to {OUTPUT}")

if __name__ == "__main__":
    main()
