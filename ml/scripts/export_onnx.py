# RF 最终训练并导出 ONNX。输出: rf_model.onnx, metrics_final.json
# Retrain RF and export ONNX. Outputs: rf_model.onnx, metrics_final.json
import json
import sys
import time
from pathlib import Path
import joblib
import numpy as np
import onnxruntime as ort
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import RandomForestClassifier

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
MODEL_PATH = ROOT / "data" / "rf_final.joblib"
ONNX_PATH = ROOT / "artifacts" / "rf_model.onnx"
METRICS_PATH = ROOT / "artifacts" / "metrics_final.json"
SEED = 42
BENIGN = 0

# 告警和自动封禁的置信度阈值
# Confidence thresholds for alerts and automatic blocking
RF_CONFIDENCE_THRESHOLD = 0.60
AUTO_BLOCK_THRESHOLD = 0.80
PROB_TOLERANCE = 1e-5


# 良性误报率与各攻击召回
# Benign FPR and per-attack recall.
def summarize(y_true, y_pred, class_names):
    benign_mask = y_true == BENIGN
    false_alerts = y_pred[benign_mask] != BENIGN
    out = {"benign_fpr": float(false_alerts.mean())}
    for idx, name in enumerate(class_names):
        if idx == BENIGN:
            continue
        mask = y_true == idx
        correct_predictions = y_pred[mask] == idx
        out[f"{name}_recall"] = float(correct_predictions.mean())
    return out


def fmt(row):
    recalls = []
    for name, value in row.items():
        if name.endswith("_recall"):
            attack_name = name.removesuffix("_recall")
            recalls.append(f"{attack_name} {value:.2%}")
    return f"FPR {row['benign_fpr']:.4%} | " + ", ".join(recalls)


def main():
    data = np.load(DATA_PATH)
    # train+val 训练
    # train on train+val
    X_fit = np.concatenate([data["X_train"], data["X_val"]])
    y_fit = np.concatenate([data["y_train"], data["y_val"]])
    X_test = data["X_test"]
    y_test = data["y_test"]
    class_names = data["class_names"].tolist()
    feature_names = data["feature_names"].tolist()

    model = RandomForestClassifier(
        n_estimators=100, min_samples_leaf=5, n_jobs=-1, random_state=SEED
    )
    start = time.perf_counter()
    model.fit(X_fit, y_fit)
    print(f"Final fit: {time.perf_counter() - start:.1f}s on {len(y_fit):,} rows (train+val)")

    proba = model.predict_proba(X_test)
    y_pred = np.argmax(proba, axis=1)
    confidence = proba.max(axis=1)

    print("\n=== Final test-set metrics ===")
    views = {"argmax": summarize(y_test, y_pred, class_names)}
    print(f"    argmax          {fmt(views['argmax'])}")
    thresholds = [("monitor", RF_CONFIDENCE_THRESHOLD), ("autoblock", AUTO_BLOCK_THRESHOLD)]
    for label, threshold in thresholds:
        # 低于阈值的攻击预测不计为告警
        # Attack predictions below the threshold do not count as alerts
        low_confidence_attack = (y_pred != BENIGN) & (confidence < threshold)
        gated = np.where(low_confidence_attack, BENIGN, y_pred)
        views[label] = {"threshold": threshold}
        views[label].update(summarize(y_test, gated, class_names))
        print(f"    conf >= {threshold:.2f}    {fmt(views[label])}")

    onnx_model = convert_sklearn(
        model,
        initial_types=[("input", FloatTensorType([None, len(feature_names)]))],
        # C# OnnxRuntime 需要普通张量
        # plain tensor for C#
        options={id(model): {"zipmap": False}},
    )
    metadata = {
        "feature_names": json.dumps(feature_names),
        "class_names": json.dumps(class_names),
        "rf_confidence_threshold": str(RF_CONFIDENCE_THRESHOLD),
        "auto_block_confidence_threshold": str(AUTO_BLOCK_THRESHOLD),
        "trained_rows": str(len(y_fit)),
        "seed": str(SEED),
    }
    for key, value in metadata.items():
        prop = onnx_model.metadata_props.add()
        prop.key = key
        prop.value = value

    ONNX_PATH.parent.mkdir(parents=True, exist_ok=True)
    ONNX_PATH.write_bytes(onnx_model.SerializeToString())

    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    start = time.perf_counter()
    ort_labels, ort_probs = session.run(None, {"input": X_test})
    ort_seconds = time.perf_counter() - start

    label_match = float((ort_labels == y_pred).mean())
    prob_diff = float(np.abs(ort_probs - proba).max())
    print("\n=== ONNX parity (sklearn vs onnxruntime, full test set) ===")
    print(f"    label match  : {label_match:.4%}")
    print(f"    max prob diff: {prob_diff:.2e}")
    print(f"    throughput   : {len(X_test) / ort_seconds:,.0f} flows/s "
          f"({ort_seconds * 1000 / len(X_test):.4f} ms/flow)")
    assert label_match == 1.0, "ONNX labels diverge from sklearn"
    assert prob_diff <= PROB_TOLERANCE, "ONNX probabilities diverge beyond tolerance"

    joblib.dump(model, MODEL_PATH, compress=3)
    metrics = {
        "model": "RandomForestClassifier(n_estimators=100, min_samples_leaf=5)",
        "seed": SEED,
        "trained_rows": int(len(y_fit)),
        "test_rows": int(len(y_test)),
        "views": views,
        "onnx": {
            "path": ONNX_PATH.name,
            "size_mb": round(ONNX_PATH.stat().st_size / 1e6, 1),
            "label_match": label_match,
            "max_prob_diff": prob_diff,
            "flows_per_second": round(len(X_test) / ort_seconds),
        },
    }
    metrics_json = json.dumps(metrics, indent=2)
    METRICS_PATH.write_text(metrics_json, encoding="utf-8")

    print(f"\nSaved {ONNX_PATH} ({ONNX_PATH.stat().st_size / 1e6:.1f} MB)")
    print(f"Saved {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1e6:.1f} MB)")
    print(f"Saved {METRICS_PATH}")


if __name__ == "__main__":
    main()
