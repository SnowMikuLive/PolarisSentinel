import sys

import numpy as np
import pandas as pd
import sklearn
import skl2onnx
import onnxruntime as ort
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

N_FEATURES = 20
N_CLASSES = 4  # Benign, DoS, PortScan, BruteForce
SEED = 42

LABEL_MATCH_REQUIRED = 1.0
PROB_TOLERANCE = 1e-5


def main() -> None:
    print(f"Python       : {sys.version.split()[0]}")
    print(f"numpy        : {np.__version__}")
    print(f"pandas       : {pd.__version__}")
    print(f"scikit-learn : {sklearn.__version__}")
    print(f"skl2onnx     : {skl2onnx.__version__}")
    print(f"onnxruntime  : {ort.__version__}")
    print("-" * 40)

    X, y = make_classification(
        n_samples=4000,
        n_features=N_FEATURES,
        n_informative=12,
        n_classes=N_CLASSES,
        n_clusters_per_class=2,
        random_state=SEED,
    )
    X = X.astype(np.float32)
    X_train, X_test, y_train, _ = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=SEED
    )

    model = RandomForestClassifier(n_estimators=50, random_state=SEED, n_jobs=-1)
    model.fit(X_train, y_train)
    skl_labels = model.predict(X_test)
    skl_probs = model.predict_proba(X_test)

    # zipmap=False -> probabilities come back as a plain float tensor,
    # which is what the C# OnnxRuntime consumer expects in Sprint 3.
    onnx_model = convert_sklearn(
        model,
        initial_types=[("input", FloatTensorType([None, N_FEATURES]))],
        options={id(model): {"zipmap": False}},
    )

    session = ort.InferenceSession(
        onnx_model.SerializeToString(), providers=["CPUExecutionProvider"]
    )
    ort_labels, ort_probs = session.run(None, {"input": X_test})

    label_match = float((ort_labels == skl_labels).mean())
    prob_diff = float(np.abs(ort_probs - skl_probs).max())

    print(f"label match  : {label_match:.4%}")
    print(f"max prob diff: {prob_diff:.2e}")

    assert label_match == LABEL_MATCH_REQUIRED, "ONNX labels diverge from sklearn"
    assert prob_diff <= PROB_TOLERANCE, "ONNX probabilities diverge beyond tolerance"
    print("SMOKE TEST PASSED")


if __name__ == "__main__":
    main()
