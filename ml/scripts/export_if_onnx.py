#IF导出ONNX并验收阈值一致性。输出:if_model.onnx,metrics_if_final.json
#Export IF to ONNX and validate threshold parity. Outputs:if_model.onnx,metrics_if_final.json
import json
import sys
import time
from pathlib import Path
import joblib
import numpy as np
import onnxruntime as ort
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from evaluate_inference import rf_alert_mask

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
NOVELTY_PATH = ROOT / "data" / "novelty.npz"
WINNER_PATH = ROOT / "data" / "if_winner.joblib"
RF_PATH = ROOT / "artifacts" / "rf_model.onnx"
SYSTEM_METRICS_PATH = ROOT / "artifacts" / "metrics_if_system.json"
ONNX_PATH = ROOT / "artifacts" / "if_model.onnx"
METRICS_PATH = ROOT / "artifacts" / "metrics_if_final.json"

BENIGN = 0

#float32分数可能有偏差，检查异常判定是否一致
#float32 scores may differ; check whether anomaly decisions agree
THRESHOLD_AGREEMENT_MIN = 0.9999
SCORE_DIFF_SANITY = 0.02
#IF转换需要ai.onnx.ml v3
#IF conversion needs ai.onnx.ml v3
TARGET_OPSET = {"": 18, "ai.onnx.ml": 3}

#RF判为攻击且达到告警阈值的样本
#RF attack predictions that meet the confidence threshold.
def rf_alerts(rf, X):
    meta = rf.get_modelmeta().custom_metadata_map
    classes = json.loads(meta["class_names"])
    proba = rf.run(["probabilities"], {rf.get_inputs()[0].name: X})[0]
    return rf_alert_mask(proba, classes.index("Benign"), float(meta["rf_confidence_threshold"]))

def main():
    model = joblib.load(WINNER_PATH)
    system = json.loads(SYSTEM_METRICS_PATH.read_text(encoding="utf-8"))
    data = np.load(DATA_PATH)
    novelty = np.load(NOVELTY_PATH, allow_pickle=False)

    feature_names = data["feature_names"].tolist()
    threshold = system["selected_threshold"]
    anchors = system["calibration_anchors"]

    onnx_model = convert_sklearn(
        model,
        initial_types=[("input", FloatTensorType([None, len(feature_names)]))],
        target_opset=TARGET_OPSET,
    )
    metadata = {
        "model_type": "IsolationForest",
        "transform": "PowerTransformer(yeo-johnson)",
        "feature_names": json.dumps(feature_names),
        "anomaly_threshold": repr(threshold),
        "score_at_confidence_060": repr(anchors["score_at_confidence_060"]),
        "score_at_confidence_095": repr(anchors["score_at_confidence_095"]),
        "if_fpr_budget": repr(system["selected_if_budget"]),
        "max_samples": str(system["selected"]["max_samples"]),
        "n_estimators": str(system["selected"]["n_estimators"]),
        "seed": str(system["seed"]),
    }
    for key, value in metadata.items():
        prop = onnx_model.metadata_props.add()
        prop.key = key
        prop.value = value

    ONNX_PATH.parent.mkdir(parents=True, exist_ok=True)
    ONNX_PATH.write_bytes(onnx_model.SerializeToString())
    size_mb = ONNX_PATH.stat().st_size / 1e6
    print(f"Exported {ONNX_PATH.name} ({size_mb:.1f} MB), threshold {threshold:.6f}")

    X_test = data["X_test"]
    y_test = data["y_test"]
    X_novelty = novelty["X_novelty"]
    benign_test = X_test[y_test == BENIGN]

    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    outputs = {}
    for index, output in enumerate(session.get_outputs()):
        outputs[output.name] = index

    def onnx_scores(X):
        results = session.run(None, {"input": X})
        scores = results[outputs["scores"]]
        return np.asarray(scores, dtype=np.float64).ravel()

    start = time.perf_counter()
    benign_scores = onnx_scores(benign_test)
    novelty_scores = onnx_scores(X_novelty)
    ort_seconds = time.perf_counter() - start

    skl_benign = model.decision_function(benign_test)
    skl_novelty = model.decision_function(X_novelty)

    all_onnx_scores = np.concatenate([benign_scores, novelty_scores])
    all_sklearn_scores = np.concatenate([skl_benign, skl_novelty])
    diff = np.abs(all_onnx_scores - all_sklearn_scores)
    onnx_anomalies = all_onnx_scores < threshold
    sklearn_anomalies = all_sklearn_scores < threshold
    flag_match = float((onnx_anomalies == sklearn_anomalies).mean())

    print("\n=== ONNX parity (sklearn vs onnxruntime, full test + novelty) ===")
    print(f"    score diff median / p99.9 / max : "
          f"{np.median(diff):.2e} / {np.quantile(diff, 0.999):.2e} / {diff.max():.2e}")
    print(f"    rows with diff > 1e-4           : {(diff > 1e-4).mean():.2%}")
    print(f"    threshold agreement             : {flag_match:.4%}")
    print(f"    throughput                      : "
          f"{(len(benign_test) + len(X_novelty)) / ort_seconds:,.0f} flows/s")
    assert diff.max() <= SCORE_DIFF_SANITY, "ONNX scores diverge far beyond float32 rounding"
    assert flag_match >= THRESHOLD_AGREEMENT_MIN, "ONNX and sklearn disagree on anomalous flows"

    rf = ort.InferenceSession(str(RF_PATH), providers=["CPUExecutionProvider"])
    benign_rf = rf_alerts(rf, benign_test)
    novelty_rf = rf_alerts(rf, X_novelty)

    rf_fpr = float(benign_rf.mean())
    # 与 C# 一致：IF 检查 RF 未告警的流，包含低置信度攻击类。
    # Match C#: IF checks flows RF did not alert on, including low-confidence attacks.
    benign_if_alerts = ~benign_rf & (benign_scores < threshold)
    if_extra = float(benign_if_alerts.mean())
    if_catch = ~novelty_rf & (novelty_scores < threshold)
    combined = novelty_rf | if_catch

    groups = novelty["groups"]
    per_group = {}
    for group in sorted(set(groups.tolist())):
        group_mask = groups == group
        per_group[group] = float(combined[group_mask].mean())

    skl_if_extra = float((~benign_rf & (skl_benign < threshold)).mean())

    print("\n=== Combined RF + IF on the test set (ONNX scores) ===")
    print(f"    system benign FPR : {rf_fpr + if_extra:.4%} (RF {rf_fpr:.4%} + IF {if_extra:.4%}; "
          f"sklearn IF would give {skl_if_extra:.4%})")
    print(f"    novelty detected  : {combined.mean():.1%} "
          f"(RF names {novelty_rf.mean():.1%}, IF adds {if_catch.mean():.1%})")
    group_results = []
    for group, rate in per_group.items():
        group_results.append(f"{group} {rate:.0%}")
    print("    " + ", ".join(group_results))

    metrics = {
        "onnx": {
            "path": ONNX_PATH.name,
            "size_mb": round(size_mb, 1),
            "score_diff_median": float(np.median(diff)),
            "score_diff_p999": float(np.quantile(diff, 0.999)),
            "score_diff_max": float(diff.max()),
            "threshold_agreement": flag_match,
            "flows_per_second": round((len(benign_test) + len(X_novelty)) / ort_seconds),
        },
        "metadata": metadata,
        "test_set": {
            "benign_rows": int(len(benign_test)),
            "novelty_rows": int(len(X_novelty)),
            "rf_benign_fpr": rf_fpr,
            "if_extra_fpr": if_extra,
            "system_benign_fpr": rf_fpr + if_extra,
            "novelty_rf_named": float(novelty_rf.mean()),
            "novelty_if_added": float(if_catch.mean()),
            "novelty_combined": float(combined.mean()),
            "novelty_per_group": per_group,
        },
    }
    metrics_json = json.dumps(metrics, indent=2)
    METRICS_PATH.write_text(metrics_json, encoding="utf-8")
    print(f"\nSaved {METRICS_PATH}")

if __name__ == "__main__":
    main()