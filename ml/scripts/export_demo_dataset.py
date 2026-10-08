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

def main():
    rf_path = ROOT / "artifacts" / "rf_model.onnx"
    if_path = ROOT / "artifacts" / "if_model.onnx"
    rf = ort.InferenceSession(str(rf_path))
    detector = ort.InferenceSession(str(if_path))
    rf_meta = rf.get_modelmeta().custom_metadata_map
    if_meta = detector.get_modelmeta().custom_metadata_map
    features = json.loads(rf_meta["feature_names"])
    benign = json.loads(rf_meta["class_names"]).index("Benign")
    threshold = float(if_meta["anomaly_threshold"])
    rng = np.random.default_rng(SEED)

    with np.load(ROOT / "data" / "prepared.npz", allow_pickle=False) as data:
        x_test, y_test = data["X_test"], data["y_test"]
        classes = data["class_names"].tolist()
        assert features == data["feature_names"].tolist()
    with np.load(ROOT / "data" / "novelty.npz", allow_pickle=False) as data:
        x_novelty, groups = data["X_novelty"], data["groups"]
        assert features == data["feature_names"].tolist()
    assert features == json.loads(if_meta["feature_names"])

    rows = []
    for label, count in (("Benign", 1000), ("DoS", 500), ("DDoS", 500)):
        source = "novelty" if label == "DDoS" else "test"
        x = x_novelty if source == "novelty" else x_test
        indices = np.flatnonzero(groups == label) if source == "novelty" else np.flatnonzero(y_test == classes.index(label))
        if label == "Benign":
            indices = rng.choice(indices, 5000, replace=False)

        matches = []
        for start in range(0, len(indices), 4096):
            batch_indices = indices[start:start + 4096]
            batch = x[batch_indices]
            probabilities = rf.run(["probabilities"], {rf.get_inputs()[0].name: batch})[0]
            scores = detector.run(["scores"], {detector.get_inputs()[0].name: batch})[0].ravel()
            rf_attack = probabilities.argmax(axis=1) != benign
            if_attack = scores.astype(np.float64) < threshold
            match = ~rf_attack & ~if_attack if label == "Benign" else rf_attack & if_attack
            matches.extend(batch_indices[match].tolist())

        selected_count = count if label == "Benign" else int(count * 0.9)
        selected = rng.choice(matches, selected_count, replace=False)
        remaining = np.setdiff1d(indices, selected)
        random_rows = rng.choice(remaining, count - selected_count, replace=False)
        for index in selected:
            rows.append((x[index], label, source, int(index), "model_selected"))
        for index in random_rows:
            rows.append((x[index], label, source, int(index), "random"))
        print(f"{label}: {selected_count} selected + {len(random_rows)} random", flush=True)

    rng.shuffle(rows)
    assert len(rows) == 2000 and np.isfinite(np.array([row[0] for row in rows])).all()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(features + ["label"])
        for values, label, _, _, _ in rows:
            writer.writerow(values.tolist() + [label])

    sources = {"test": ROOT / "data" / "prepared.npz", "novelty": ROOT / "data" / "novelty.npz"}
    details = {
        "purpose": "Curated demonstration only; not an independent performance test.",
        "selection": "Benign rows classified normal by both models. Attack rows: 90% detected by both models, 10% randomly sampled from the remaining original rows.",
        "seed": SEED,
        "class_counts": {"Benign": 1000, "DoS": 500, "DDoS": 500},
        "source_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sources.items()},
        "model_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (rf_path, if_path)},
        "if_threshold": threshold,
        "novelty_note": "novelty.npz was used during IF model selection; these rows are not independent test data.",
        "row_sources": [[source, index, selection] for _, _, source, index, selection in rows],
    }
    OUTPUT.with_suffix(".json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(f"Exported {len(rows)} demonstration rows to {OUTPUT}")

if __name__ == "__main__":
    main()