# IF ONNX 导出可行性验证。仅打印，不写文件
# Spike test for IF ONNX export. Prints only, no files written.

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
# IF 转换需要 ai.onnx.ml v3
# IF conversion needs ai.onnx.ml v3
TARGET_OPSET = {"": 18, "ai.onnx.ml": 3}


# 合成重尾数据
# Synthetic heavy-tailed data.
def heavy_tailed_sample(rows):
    rng = np.random.default_rng(SEED)
    normal_values = rng.normal(0.0, 4.0, size=(rows, N_FEATURES))
    sample = np.exp(normal_values)
    return sample.astype(np.float32)


# 尝试转换并校验一致性
# Attempt conversion and verify parity.
def try_convert(name, model, X):
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
    outputs = {}
    for index, output in enumerate(session.get_outputs()):
        outputs[output.name] = index
    results = session.run(None, {"input": X})

    ort_labels = results[outputs["label"]].ravel()
    ort_scores = np.asarray(results[outputs["scores"]]).ravel()

    sklearn_labels = model.predict(X)
    label_match = float((ort_labels == sklearn_labels).mean())
    decision_scores = model.decision_function(X)
    sample_scores = model.score_samples(X)
    diffs = {
        "decision_function": float(np.abs(ort_scores - decision_scores).max()),
        "score_samples": float(np.abs(ort_scores - sample_scores).max()),
    }
    matched = min(diffs, key=diffs.get)

    size_kb = len(onnx_model.SerializeToString()) / 1024
    print(f"{name:<28} labels {label_match:>8.2%} | {matched} diff {diffs[matched]:.2e} | "
          f"{size_kb:>7.1f} KB")
    return label_match == 1.0 and diffs[matched] <= TOLERANCE


def main():
    X = heavy_tailed_sample(5000)
    X_test = heavy_tailed_sample(1000)

    candidates = {
        "IsolationForest (raw)": IsolationForest(n_estimators=100, random_state=SEED),
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
        if ok:
            status = "PASS"
        else:
            status = "FAIL"
        print(f"    {status}  {name}")
    if not verdict["IsolationForest (raw)"]:
        raise SystemExit("Isolation Forest cannot be exported; fall back plan required")


if __name__ == "__main__":
    main()
