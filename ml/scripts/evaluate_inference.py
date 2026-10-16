# 用已导出的 RF 和 IF 评估实际分流，不训练模型。
# Evaluate routing with both exported ONNX models; no training.
import hashlib
import json
from pathlib import Path
import numpy as np
import onnxruntime as ort

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"

def rf_alert_mask(probabilities, benign, threshold):
    return ((probabilities.argmax(axis=1) != benign)
            & (probabilities.max(axis=1) >= np.float32(threshold)))

def main():
    rf = ort.InferenceSession(str(ARTIFACTS / "rf_model.onnx"))
    detector = ort.InferenceSession(str(ARTIFACTS / "if_model.onnx"))
    rf_meta = rf.get_modelmeta().custom_metadata_map
    if_meta = detector.get_modelmeta().custom_metadata_map
    classes = json.loads(rf_meta["class_names"])
    features = json.loads(rf_meta["feature_names"])
    assert features == json.loads(if_meta["feature_names"])
    benign = classes.index("Benign")
    rf_threshold = float(rf_meta["rf_confidence_threshold"])
    if_threshold = float(if_meta["anomaly_threshold"])
    metrics = {
        "routing": "RF non-Benign and confidence >= RF threshold; otherwise IF; IF score < threshold is Unknown_Anomaly; otherwise Benign",
        "scope": "Offline model detection only; excludes capture, PreFilter, policy matching and firewall execution.",
        "novelty_note": "Full novelty.npz was reused during IF selection; this is not an independent novelty test set.",
        "rf_threshold": rf_threshold,
        "if_threshold": if_threshold,
        "model_sha256": {name: hashlib.sha256((ARTIFACTS / name).read_bytes()).hexdigest()
                         for name in ("rf_model.onnx", "if_model.onnx")},
        "populations": {},
    }
    cases = {}
    data = np.load(ROOT / "data" / "prepared.npz")
    novelty = np.load(ROOT / "data" / "novelty.npz", allow_pickle=False)
    assert features == data["feature_names"].tolist() == novelty["feature_names"].tolist()

    for population, x, groups in (
        ("test", data["X_test"], np.array(classes)[data["y_test"]]),
        ("novelty", novelty["X_novelty"], novelty["groups"]),
    ):
        print(f"Scoring {population}: {len(x)} rows", flush=True)
        probabilities = []
        scores = []
        for start in range(0, len(x), 4096):
            batch = x[start:start + 4096]
            probabilities.append(rf.run(["probabilities"], {rf.get_inputs()[0].name: batch})[0])
            scores.append(detector.run(["scores"], {detector.get_inputs()[0].name: batch})[0].ravel())
        probabilities = np.concatenate(probabilities)
        scores = np.concatenate(scores)
        best = probabilities.argmax(axis=1)
        confidence = probabilities.max(axis=1)
        rf_alerts = rf_alert_mask(probabilities, benign, rf_threshold)
        # 转 double 后比较，与 C# float 分数转 double 一致。
        # Match C# promotion of the float score to double.
        anomalies = scores.astype(np.float64) < if_threshold
        if_added = ~rf_alerts & anomalies
        combined = rf_alerts | if_added
        # 同步前引擎直接返回所有 RF 攻击类，不检查置信度。
        # Previous engine returned all RF attack classes without a confidence check.
        previous = (best != benign) | ((best == benign) & anomalies)
        rows = {}
        for group in sorted(set(groups.tolist())):
            mask = groups == group
            rows[group] = {
                "rows": int(mask.sum()),
                "rf_alerts": int(rf_alerts[mask].sum()),
                "if_added": int(if_added[mask].sum()),
                "combined_detected": int(combined[mask].sum()),
                "rf_rate": float(rf_alerts[mask].mean()),
                "combined_rate": float(combined[mask].mean()),
                "previous_engine_rate": float(previous[mask].mean()),
            }
        rows["total"] = {"rows": len(x), "rf_rate": float(rf_alerts.mean()),
                         "combined_rate": float(combined.mean())}
        metrics["populations"][population] = rows

        # 留下少量真实输入，供 C# 检查同一条路径。
        # Keep a few real inputs for C# routing checks.
        masks = {"rf_attack": rf_alerts, "benign_normal": (best == benign) & ~anomalies,
                 "benign_anomaly": (best == benign) & anomalies,
                 "low_rf_normal": (best != benign) & ~rf_alerts & ~anomalies,
                 "low_rf_anomaly": (best != benign) & ~rf_alerts & anomalies}
        for name, mask in masks.items():
            if name in cases or not mask.any():
                continue
            i = int(np.flatnonzero(mask)[0])
            source = "RandomForest" if rf_alerts[i] else "IsolationForest" if if_added[i] else "None"
            label = classes[best[i]] if rf_alerts[i] else "Unknown_Anomaly" if if_added[i] else "Benign"
            expected_confidence = float(confidence[i] if rf_alerts[i] else probabilities[i, benign])
            if if_added[i]:
                low = float(if_meta["score_at_confidence_060"])
                high = float(if_meta["score_at_confidence_095"])
                expected_confidence = float(np.clip(0.60 + 0.35 * (low - float(scores[i])) / (low - high), 0.60, 0.99))
            cases[name] = {"population": population, "row": i, "features": x[i].tolist(),
                           "attackType": label, "source": source, "confidence": expected_confidence,
                           "rfOnlyAttackType": classes[best[i]] if rf_alerts[i] else "Benign",
                           "rfOnlySource": "RandomForest" if rf_alerts[i] else "None"}

    (ARTIFACTS / "metrics_inference.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (ARTIFACTS / "inference_cases.json").write_text(json.dumps(cases, indent=2), encoding="utf-8")
    print(json.dumps(metrics["populations"], indent=2))

if __name__ == "__main__":
    main()