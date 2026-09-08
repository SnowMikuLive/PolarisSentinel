"""验证导出的随机森林 ONNX 模型与 sklearn 一致，且元数据符合 C# 端契约。
Verify exported RF ONNX matches sklearn and metadata matches the C# contract.

依赖产物（不存在时跳过）:
- ml/data/prepared.npz      由 prepare_dataset.py 生成
  produced by prepare_dataset.py
- ml/data/rf_final.joblib   由 export_onnx.py 生成
  produced by export_onnx.py
- ml/artifacts/rf_model.onnx 由 export_onnx.py 生成
  produced by export_onnx.py
"""

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
    """ONNX 推理结果（标签与概率）应与 sklearn 完全一致。
    ONNX inference labels and probabilities must match sklearn exactly."""
    model = joblib.load(MODEL_PATH)
    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    X_test = np.load(DATA_PATH)["X_test"]

    rng = np.random.default_rng(42)
    sample = X_test[rng.choice(len(X_test), size=50_000, replace=False)]

    skl_proba = model.predict_proba(sample)
    ort_labels, ort_proba = session.run(None, {"input": sample})

    assert (ort_labels == np.argmax(skl_proba, axis=1)).all()
    assert np.abs(ort_proba - skl_proba).max() <= 1e-5


@needs_artifacts
def test_onnx_metadata_matches_schema():
    """ONNX 元数据中的特征名、类别顺序和策略阈值应与训练脚本一致。
    ONNX metadata feature names, class order, and thresholds must match training scripts."""
    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    meta = session.get_modelmeta().custom_metadata_map

    assert json.loads(meta["feature_names"]) == FEATURE_NAMES
    assert json.loads(meta["class_names"]) == CLASS_NAMES
    assert float(meta["rf_confidence_threshold"]) == pytest.approx(0.60)
    assert float(meta["auto_block_confidence_threshold"]) == pytest.approx(0.80)

    (input_info,) = session.get_inputs()
    assert input_info.shape[1] == len(FEATURE_NAMES)
    assert input_info.type == "tensor(float)"
