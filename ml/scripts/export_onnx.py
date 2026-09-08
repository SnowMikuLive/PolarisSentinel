"""在 train+val 上重训最终随机森林，导出 ONNX 并验证与 sklearn 的一致性。
Retrain on train+val, export the final Random Forest to ONNX, and verify parity.

将特征名、类别顺序和策略阈值写入 ONNX 元数据，C# 端无需硬编码。
Embeds feature names, class order, and policy thresholds into ONNX metadata.

输出:
- ml/artifacts/rf_model.onnx       C# 推理用 ONNX 模型
  ONNX model for C# inference
- ml/data/rf_final.joblib          sklearn 模型存档
  sklearn model archive
- ml/artifacts/metrics_final.json  测试集指标 + ONNX 一致性报告
  test-set metrics + ONNX parity report
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
from sklearn.ensemble import RandomForestClassifier

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
MODEL_PATH = ROOT / "data" / "rf_final.joblib"
ONNX_PATH = ROOT / "artifacts" / "rf_model.onnx"
METRICS_PATH = ROOT / "artifacts" / "metrics_final.json"
SEED = 42
BENIGN = 0

# 需与 C# PolicySettings 保持一致
# Must match PolicySettings in C#
RF_CONFIDENCE_THRESHOLD = 0.60   # 告警阈值 — alert tier
AUTO_BLOCK_THRESHOLD = 0.80      # 封禁阈值 — block tier
PROB_TOLERANCE = 1e-5            # sklearn 与 ONNX 概率最大允许偏差
                                  # Max allowed sklearn vs ONNX probability diff


def summarize(y_true: np.ndarray, y_pred: np.ndarray, class_names: list[str]) -> dict:
    """计算良性误报率与各攻击类召回率。
    Compute benign FPR and per-attack recall."""
    benign_mask = y_true == BENIGN
    out = {"benign_fpr": float((y_pred[benign_mask] != BENIGN).mean())}
    for idx, name in enumerate(class_names):
        if idx == BENIGN:
            continue
        mask = y_true == idx
        out[f"{name}_recall"] = float((y_pred[mask] == idx).mean())
    return out


def fmt(row: dict) -> str:
    """格式化单行指标用于控制台输出。
    Format one metrics row for console output."""
    return (f"FPR {row['benign_fpr']:.4%} | "
            + ", ".join(f"{k.removesuffix('_recall')} {v:.2%}"
                        for k, v in row.items() if k.endswith("_recall")))


def main() -> None:
    data = np.load(DATA_PATH)
    # 最终模型使用除测试集外的全部标注数据
    # Final model uses all labelled data except the held-out test set
    X_fit = np.concatenate([data["X_train"], data["X_val"]])
    y_fit = np.concatenate([data["y_train"], data["y_val"]])
    X_test, y_test = data["X_test"], data["y_test"]
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
    for label, t in [("monitor", RF_CONFIDENCE_THRESHOLD), ("autoblock", AUTO_BLOCK_THRESHOLD)]:
        # 策略视角：置信度不足的攻击预测降级为良性
        # Policy view: low-confidence attack predictions are treated as benign
        gated = np.where((y_pred != BENIGN) & (confidence < t), BENIGN, y_pred)
        views[label] = {"threshold": t, **summarize(y_test, gated, class_names)}
        print(f"    conf >= {t:.2f}    {fmt(views[label])}")

    # zipmap=False → 概率输出为普通张量（C# OnnxRuntime 需要）
    # zipmap=False → probabilities as plain tensor (required by C# OnnxRuntime)
    onnx_model = convert_sklearn(
        model,
        initial_types=[("input", FloatTensorType([None, len(feature_names)]))],
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
        prop.key, prop.value = key, value

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
    METRICS_PATH.write_text(json.dumps({
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
    }, indent=2), encoding="utf-8")

    print(f"\nSaved {ONNX_PATH} ({ONNX_PATH.stat().st_size / 1e6:.1f} MB)")
    print(f"Saved {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1e6:.1f} MB)")
    print(f"Saved {METRICS_PATH}")


if __name__ == "__main__":
    main()
