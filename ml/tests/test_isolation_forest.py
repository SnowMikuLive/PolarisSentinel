"""验证孤立森林新类攻击留出集契约与 IF ONNX 导出质量。
Verify Isolation Forest novelty holdout contract and IF ONNX export quality.

依赖产物（不存在时跳过）:
- ml/data/novelty.npz              由 prepare_novelty.py 生成
  produced by prepare_novelty.py
- ml/data/if_winner.joblib         由 tune_if.py 生成
  produced by tune_if.py
- ml/artifacts/if_model.onnx       由 export_if_onnx.py 生成
  produced by export_if_onnx.py
- ml/artifacts/metrics_if_system.json  由 tune_if.py 生成
  produced by tune_if.py
"""

import json
from pathlib import Path

import joblib
import numpy as np
import onnxruntime as ort
import pytest

from prepare_dataset import FEATURE_NAMES, LABEL_MAPPING
from prepare_novelty import classify

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
NOVELTY_PATH = ROOT / "data" / "novelty.npz"
WINNER_PATH = ROOT / "data" / "if_winner.joblib"
ONNX_PATH = ROOT / "artifacts" / "if_model.onnx"
SYSTEM_METRICS_PATH = ROOT / "artifacts" / "metrics_if_system.json"

needs_novelty = pytest.mark.skipif(not NOVELTY_PATH.exists(), reason="run prepare_novelty.py first")
needs_artifacts = pytest.mark.skipif(
    not (ONNX_PATH.exists() and WINNER_PATH.exists() and DATA_PATH.exists()
         and NOVELTY_PATH.exists() and SYSTEM_METRICS_PATH.exists()),
    reason="run tune_if.py and export_if_onnx.py first",
)


def test_novelty_groups_are_disjoint_from_known_labels():
    """新类攻击标签不得出现在 RF 训练映射表中。
    Novelty attack labels must not appear in the RF training label mapping."""
    for label in LABEL_MAPPING:
        assert classify(label) is None
    assert classify("DDoS") == "DDoS"
    assert classify("Bot") == "Bot"
    assert classify("Infiltration") == "Infiltration"
    assert classify("Heartbleed") == "Heartbleed"
    for label in ("Web Attack \ufffd Brute Force", "Web Attack \ufffd XSS",
                  "Web Attack \ufffd Sql Injection"):
        assert classify(label) == "WebAttack"


@needs_novelty
def test_novelty_arrays_share_the_feature_contract():
    """留出集特征维度、dtype 和攻击族标签应符合契约。
    Holdout feature shape, dtype, and attack-group labels must match the contract."""
    novelty = np.load(NOVELTY_PATH, allow_pickle=False)
    X = novelty["X_novelty"]
    assert novelty["feature_names"].tolist() == FEATURE_NAMES
    assert X.dtype == np.float32
    assert X.shape[1] == len(FEATURE_NAMES)
    assert np.isfinite(X).all()
    assert len(novelty["groups"]) == len(X)
    assert set(novelty["groups"].tolist()) == {"DDoS", "Bot", "WebAttack", "Infiltration", "Heartbleed"}


@needs_artifacts
def test_if_onnx_agrees_with_sklearn_on_anomaly_decisions():
    """IF ONNX 与 sklearn 在异常阈值判定上应高度一致（生产路径验收标准）。
    IF ONNX and sklearn must agree on anomaly threshold decisions (production acceptance)."""
    model = joblib.load(WINNER_PATH)
    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    threshold = float(session.get_modelmeta().custom_metadata_map["anomaly_threshold"])

    data = np.load(DATA_PATH)
    benign = data["X_test"][data["y_test"] == 0]
    novelty = np.load(NOVELTY_PATH, allow_pickle=False)["X_novelty"]
    rng = np.random.default_rng(42)
    sample = np.concatenate([
        benign[rng.choice(len(benign), size=20_000, replace=False)],
        novelty[rng.choice(len(novelty), size=10_000, replace=False)],
    ])

    outputs = {o.name: i for i, o in enumerate(session.get_outputs())}
    ort_scores = np.asarray(session.run(None, {"input": sample})[outputs["scores"]]).ravel()
    skl_scores = model.decision_function(sample)

    diff = np.abs(ort_scores - skl_scores)
    assert np.median(diff) < 1e-6
    # float32 切分阈值导致少数行偏差；详见 export_if_onnx.py
    # float32 split thresholds shift a few rows; see export_if_onnx.py
    assert diff.max() < 0.02
    agreement = ((ort_scores < threshold) == (skl_scores < threshold)).mean()
    assert agreement >= 0.9999


@needs_artifacts
def test_if_onnx_metadata_matches_tuning_result():
    """IF ONNX 元数据中的阈值和校准锚点应与 tune_if.py 结果一致。
    IF ONNX metadata threshold and calibration anchors must match tune_if.py results."""
    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    meta = session.get_modelmeta().custom_metadata_map
    system = json.loads(SYSTEM_METRICS_PATH.read_text(encoding="utf-8"))

    assert json.loads(meta["feature_names"]) == FEATURE_NAMES
    assert meta["model_type"] == "IsolationForest"
    assert float(meta["anomaly_threshold"]) == pytest.approx(system["selected_threshold"])

    at_060 = float(meta["score_at_confidence_060"])
    at_095 = float(meta["score_at_confidence_095"])
    # 分数越低越异常；两个锚点均位于异常尾部，095 比 060 更极端
    # Lower scores are more anomalous; both anchors sit in the anomalous tail, 095 < 060 < 0
    assert at_060 == pytest.approx(float(meta["anomaly_threshold"]))
    assert at_095 < at_060 < 0

    (input_info,) = session.get_inputs()
    assert input_info.shape[1] == len(FEATURE_NAMES)
    assert input_info.type == "tensor(float)"
    assert {o.name for o in session.get_outputs()} == {"label", "scores"}
