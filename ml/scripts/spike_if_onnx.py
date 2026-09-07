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

# skl2onnx 1.20 does not emit ai.onnx.ml v4 yet; the IsolationForest converter
# needs the domain pinned to v3.
TARGET_OPSET = {"": 18, "ai.onnx.ml": 3}


def heavy_tailed_sample(rows: int) -> np.ndarray:
    # mimics the real feature distribution: durations/rates span several orders of magnitude
    rng = np.random.default_rng(SEED)
    return np.exp(rng.normal(0.0, 4.0, size=(rows, N_FEATURES))).astype(np.float32)


def try_convert(name: str, model, X: np.ndarray) -> bool:
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
    # Identify which sklearn scoring function the ONNX "scores" output corresponds to,
    # so the C# side knows exactly what it is reading.
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
        # output_distribution="normal" has no converter; uniform does.
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
