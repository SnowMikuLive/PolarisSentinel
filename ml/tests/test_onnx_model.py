# RF ONNX 一致性测试。需先运行 prepare_dataset.py 和 export_onnx.py
# RF ONNX parity tests. Requires prepare_dataset.py and export_onnx.py first.

import json
from pathlib import Path

import joblib
import numpy as np
import onnxruntime as ort
import pytest

from prepare_dataset import CLASS_NAMES, FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[1]
ONNX_PATH = ROOT / "artifacts" / "rf_model.onnx"
MODEL_PATH = ROOT / "data" / "rf_final.joblib"
DATA_PATH = ROOT / "data" / "prepared.npz"

needs_artifacts = pytest.mark.skipif(
    not (ONNX_PATH.exists() and MODEL_PATH.exists() and DATA_PATH.exists()),
    reason="run prepare_dataset.py and export_onnx.py first",
)


@needs_artifacts
def test_onnx_parity_with_sklearn():
    # Arrange
    model = joblib.load(MODEL_PATH)
    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    data = np.load(DATA_PATH)
    X_test = data["X_test"]

    rng = np.random.default_rng(42)
    sample_indices = rng.choice(len(X_test), size=50_000, replace=False)
    sample = X_test[sample_indices]

    # Act
    skl_proba = model.predict_proba(sample)
    ort_labels, ort_proba = session.run(None, {"input": sample})
    skl_labels = np.argmax(skl_proba, axis=1)
    matching_labels = ort_labels == skl_labels
    probability_diff = np.abs(ort_proba - skl_proba)

    # Assert
    assert matching_labels.all()
    assert probability_diff.max() <= 1e-5


@needs_artifacts
def test_onnx_metadata_matches_schema():
    # Arrange
    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])

    # Act
    model_meta = session.get_modelmeta()
    meta = model_meta.custom_metadata_map
    feature_names = json.loads(meta["feature_names"])
    class_names = json.loads(meta["class_names"])
    alert_threshold = float(meta["rf_confidence_threshold"])
    block_threshold = float(meta["auto_block_confidence_threshold"])
    inputs = session.get_inputs()

    # Assert
    assert feature_names == FEATURE_NAMES
    assert class_names == CLASS_NAMES
    assert alert_threshold == pytest.approx(0.60)
    assert block_threshold == pytest.approx(0.80)
    assert len(inputs) == 1
    input_info = inputs[0]
    assert input_info.shape[1] == len(FEATURE_NAMES)
    assert input_info.type == "tensor(float)"
