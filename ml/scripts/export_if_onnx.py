"""导出孤立森林流水线为 ONNX，并在生产路径上验收阈值一致性。
Export the Isolation Forest pipeline to ONNX and validate threshold parity on the production path.

将异常阈值、置信度校准锚点和特征 schema 写入元数据，C# 端零硬编码。
Embeds anomaly threshold, confidence calibration anchors, and feature schema into metadata.

验收标准对准 ONNX 推理路径（非逐点分数相等）:
- 阈值判定一致率 ≥ 99.99%（float32 切分阈值导致约 1.5% 行分数偏差可达 1e-2）
- 系统级 IF 误报率与 sklearn 路径差异可忽略
Acceptance targets the ONNX inference path (not per-row score equality):
- Threshold agreement ≥ 99.99% (float32 split thresholds shift ~1.5% of rows by up to 1e-2)
- System-level IF FPR difference vs sklearn path is negligible

输出:
- ml/artifacts/if_model.onnx          C# 异常检测用 ONNX 模型
  ONNX model for C# anomaly detection
- ml/artifacts/metrics_if_final.json  一致性报告 + 测试集 RF+IF 联合指标
  parity report + test-set RF+IF combined metrics
"""

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import onnxruntime as ort
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
NOVELTY_PATH = ROOT / "data" / "novelty.npz"
WINNER_PATH = ROOT / "data" / "if_winner.joblib"
RF_PATH = ROOT / "data" / "rf_final.joblib"
SYSTEM_METRICS_PATH = ROOT / "artifacts" / "metrics_if_system.json"
ONNX_PATH = ROOT / "artifacts" / "if_model.onnx"
METRICS_PATH = ROOT / "artifacts" / "metrics_if_final.json"

BENIGN = 0
RF_CONFIDENCE_THRESHOLD = 0.60

# ONNX TreeEnsemble 以 float32 存储切分阈值；经 PowerTransformer 后落在阈值邻域的
# 样本可能走不同分支，约 1.5% 行分数偏差可达 1e-2。生产路径是 ONNX，因此验收
# 标准是两侧对异常阈值的判定一致，而非逐点分数相等。
# ONNX TreeEnsemble stores split thresholds as float32; rows whose transformed value
# sits near a split may take a different branch (~1.5% of rows shift by up to 1e-2).
# Production runs ONNX, so acceptance is threshold agreement, not per-row score equality.
THRESHOLD_AGREEMENT_MIN = 0.9999
SCORE_DIFF_SANITY = 0.02

# skl2onnx 1.20 尚不支持 ai.onnx.ml v4；孤立森林转换器需固定为 v3
# skl2onnx 1.20 does not emit ai.onnx.ml v4; pin domain to v3 for IF converter
TARGET_OPSET = {"": 18, "ai.onnx.ml": 3}


def rf_alerts(rf, X: np.ndarray) -> np.ndarray:
    """RF 产生可执行（非良性）告警的位置为 True。
    True where RF raises an actionable (non-benign) alert."""
    proba = rf.predict_proba(X)
    return (proba.argmax(axis=1) != BENIGN) & (proba.max(axis=1) >= RF_CONFIDENCE_THRESHOLD)


def main() -> None:
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
        # ONNX "scores" 输出等于 sklearn decision_function；分数越低越异常
        # ONNX "scores" output equals sklearn decision_function; lower = more anomalous
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
        prop.key, prop.value = key, value

    ONNX_PATH.parent.mkdir(parents=True, exist_ok=True)
    ONNX_PATH.write_bytes(onnx_model.SerializeToString())
    size_mb = ONNX_PATH.stat().st_size / 1e6
    print(f"Exported {ONNX_PATH.name} ({size_mb:.1f} MB), threshold {threshold:.6f}")

    # 一致性校验：sklearn vs onnxruntime（真实测试集 + 新类攻击留出集）
    # Parity check: sklearn vs onnxruntime on real test + novelty holdout
    X_test, y_test = data["X_test"], data["y_test"]
    X_novelty = novelty["X_novelty"]
    benign_test = X_test[y_test == BENIGN]

    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    outputs = {o.name: i for i, o in enumerate(session.get_outputs())}

    def onnx_scores(X: np.ndarray) -> np.ndarray:
        return np.asarray(session.run(None, {"input": X})[outputs["scores"]]).ravel()

    start = time.perf_counter()
    benign_scores = onnx_scores(benign_test)
    novelty_scores = onnx_scores(X_novelty)
    ort_seconds = time.perf_counter() - start

    skl_benign = model.decision_function(benign_test)
    skl_novelty = model.decision_function(X_novelty)

    diff = np.abs(np.r_[benign_scores, novelty_scores] - np.r_[skl_benign, skl_novelty])
    flag_match = float((
        (np.r_[benign_scores, novelty_scores] < threshold)
        == (np.r_[skl_benign, skl_novelty] < threshold)
    ).mean())

    print("\n=== ONNX parity (sklearn vs onnxruntime, full test + novelty) ===")
    print(f"    score diff median / p99.9 / max : "
          f"{np.median(diff):.2e} / {np.quantile(diff, 0.999):.2e} / {diff.max():.2e}")
    print(f"    rows with diff > 1e-4           : {(diff > 1e-4).mean():.2%}")
    print(f"    threshold agreement             : {flag_match:.4%}")
    print(f"    throughput                      : "
          f"{(len(benign_test) + len(X_novelty)) / ort_seconds:,.0f} flows/s")
    assert diff.max() <= SCORE_DIFF_SANITY, "ONNX scores diverge far beyond float32 rounding"
    assert flag_match >= THRESHOLD_AGREEMENT_MIN, "ONNX and sklearn disagree on anomalous flows"

    # 验证集选定的阈值在未触碰的测试集上是否仍成立（使用 ONNX 分数，与 C# 路径一致）
    # Does the validation-chosen threshold hold on the untouched test set (ONNX scores, C# path)
    rf = joblib.load(RF_PATH)
    benign_rf = rf_alerts(rf, benign_test)
    novelty_rf = rf_alerts(rf, X_novelty)

    rf_fpr = float(benign_rf.mean())
    if_extra = float((~benign_rf & (benign_scores < threshold)).mean())
    if_catch = ~novelty_rf & (novelty_scores < threshold)
    combined = novelty_rf | if_catch

    groups = novelty["groups"]
    per_group = {g: float(combined[groups == g].mean()) for g in sorted(set(groups.tolist()))}

    skl_if_extra = float((~benign_rf & (skl_benign < threshold)).mean())

    print("\n=== Combined RF + IF on the test set (ONNX scores) ===")
    print(f"    system benign FPR : {rf_fpr + if_extra:.4%} (RF {rf_fpr:.4%} + IF {if_extra:.4%}; "
          f"sklearn IF would give {skl_if_extra:.4%})")
    print(f"    novelty detected  : {combined.mean():.1%} "
          f"(RF names {novelty_rf.mean():.1%}, IF adds {if_catch.mean():.1%})")
    print("    " + ", ".join(f"{g} {v:.0%}" for g, v in per_group.items()))

    METRICS_PATH.write_text(json.dumps({
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
    }, indent=2), encoding="utf-8")
    print(f"\nSaved {METRICS_PATH}")


if __name__ == "__main__":
    main()
