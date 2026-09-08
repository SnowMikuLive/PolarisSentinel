"""可行性验证：孤立森林（及常见流水线）能否导出为 ONNX？
Spike test: can Isolation Forest (and common pipelines) be exported to ONNX?

在确定 IF 的 ONNX 导出方案前运行；若裸 IsolationForest 无法转换则退出并报错。
Runs before committing to an IF ONNX export path. Exits non-zero if the raw
IsolationForest cannot be converted, signalling a fallback plan is needed.

不写入文件，结果仅打印到控制台。
No files are written; results print to stdout.
"""

import sys

import numpy as np
import onnxruntime as ort
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import PowerTransformer, QuantileTransformer
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

N_FEATURES = 20
SEED = 42
TOLERANCE = 1e-4

# skl2onnx 1.20 尚不支持 ai.onnx.ml v4；孤立森林转换器需固定为 v3
# skl2onnx 1.20 does not emit ai.onnx.ml v4; pin domain to v3 for IF converter
TARGET_OPSET = {"": 18, "ai.onnx.ml": 3}


def heavy_tailed_sample(rows: int) -> np.ndarray:
    """生成跨多个数量级的合成数据，模拟真实流量特征分布。
    Synthetic data spanning several orders of magnitude (like real flows)."""
    rng = np.random.default_rng(SEED)
    return np.exp(rng.normal(0.0, 4.0, size=(rows, N_FEATURES))).astype(np.float32)


def try_convert(name: str, model, X: np.ndarray) -> bool:
    """尝试 ONNX 转换，并验证标签与分数与 sklearn 一致。
    Attempt ONNX conversion and verify label/score parity with sklearn."""
    try:
        onnx_model = convert_sklearn(
            model,
            initial_types=[("input", FloatTensorType([None, N_FEATURES]))],
            target_opset=TARGET_OPSET,
        )
    except Exception as exc:
        print(f"{name:<28} CONVERSION FAILED: {type(exc).__name__}: {exc}")
        return False

    session = ort.InferenceSession(
        onnx_model.SerializeToString(), providers=["CPUExecutionProvider"]
    )
    outputs = {o.name: i for i, o in enumerate(session.get_outputs())}
    results = session.run(None, {"input": X})

    ort_labels = results[outputs["label"]].ravel()
    ort_scores = np.asarray(results[outputs["scores"]]).ravel()

    label_match = float((ort_labels == model.predict(X)).mean())
    # 确定 ONNX "scores" 输出对应 sklearn 的哪种评分函数，供 C# 端解读
    # Identify which sklearn scoring function the ONNX "scores" output maps to
    diffs = {
        "decision_function": float(np.abs(ort_scores - model.decision_function(X)).max()),
        "score_samples": float(np.abs(ort_scores - model.score_samples(X)).max()),
    }
    matched = min(diffs, key=diffs.get)

    size_kb = len(onnx_model.SerializeToString()) / 1024
    print(f"{name:<28} labels {label_match:>8.2%} | {matched} diff {diffs[matched]:.2e} | "
          f"{size_kb:>7.1f} KB")
    return label_match == 1.0 and diffs[matched] <= TOLERANCE


def main() -> None:
    X = heavy_tailed_sample(5000)
    X_test = heavy_tailed_sample(1000)

    candidates = {
        "IsolationForest (raw)": IsolationForest(n_estimators=100, random_state=SEED),
        # output_distribution="normal" 无转换器支持，uniform 可以
        # output_distribution="normal" has no converter; uniform does
        "Pipeline(Quantile + IF)": Pipeline([
            ("scale", QuantileTransformer(output_distribution="uniform", random_state=SEED)),
            ("iforest", IsolationForest(n_estimators=100, random_state=SEED)),
        ]),
        "Pipeline(PowerT + IF)": Pipeline([
            ("scale", PowerTransformer(method="yeo-johnson")),
            ("iforest", IsolationForest(n_estimators=100, random_state=SEED)),
        ]),
    }

    verdict = {}
    for name, model in candidates.items():
        model.fit(X)
        verdict[name] = try_convert(name, model, X_test)

    print()
    for name, ok in verdict.items():
        print(f"    {'PASS' if ok else 'FAIL'}  {name}")
    if not verdict["IsolationForest (raw)"]:
        raise SystemExit("Isolation Forest cannot be exported; fall back plan required")


if __name__ == "__main__":
    main()
