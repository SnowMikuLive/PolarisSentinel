#IF留出集与ONNX测试
#IF novelty holdout and ONNX tests.
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
    #Arrange
    novelty_labels = ("DDoS", "Bot", "Infiltration", "Heartbleed")
    web_labels = (
        "Web Attack \ufffd Brute Force",
        "Web Attack \ufffd XSS",
        "Web Attack \ufffd Sql Injection",
    )

    #Act
    known_results = []
    for label in LABEL_MAPPING:
        known_results.append(classify(label))
    novelty_results = {}
    for label in novelty_labels:
        novelty_results[label] = classify(label)
    web_results = []
    for label in web_labels:
        web_results.append(classify(label))
  
    #Assert
    for group in known_results:
        assert group is None
    for label in novelty_labels:
        assert novelty_results[label] == label
    for group in web_results:
        assert group == "WebAttack"

@needs_novelty
def test_novelty_arrays_share_the_feature_contract():
    #Arrange
    novelty = np.load(NOVELTY_PATH, allow_pickle=False)
    expected_groups = {"DDoS", "Bot", "WebAttack", "Infiltration", "Heartbleed"}

    #Act
    X = novelty["X_novelty"]
    feature_names = novelty["feature_names"].tolist()
    groups = novelty["groups"]
    group_names = groups.tolist()
    unique_groups = set(group_names)
    finite_values = np.isfinite(X)

    #Assert
    assert feature_names == FEATURE_NAMES
    assert X.dtype == np.float32
    assert X.shape[1] == len(FEATURE_NAMES)
    assert finite_values.all()
    assert len(groups) == len(X)
    assert unique_groups == expected_groups

@needs_artifacts
def test_if_onnx_agrees_with_sklearn_on_anomaly_decisions():
    #Arrange
    model = joblib.load(WINNER_PATH)
    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    model_meta = session.get_modelmeta()
    meta = model_meta.custom_metadata_map
    threshold = float(meta["anomaly_threshold"])

    data = np.load(DATA_PATH)
    X_test = data["X_test"]
    y_test = data["y_test"]
    benign = X_test[y_test == 0]
    novelty_data = np.load(NOVELTY_PATH, allow_pickle=False)
    novelty = novelty_data["X_novelty"]

    rng = np.random.default_rng(42)
    benign_indices = rng.choice(len(benign), size=20_000, replace=False)
    novelty_indices = rng.choice(len(novelty), size=10_000, replace=False)
    benign_sample = benign[benign_indices]
    novelty_sample = novelty[novelty_indices]
    sample = np.concatenate([benign_sample, novelty_sample])

    #Act
    output_indices = {}
    for index, output in enumerate(session.get_outputs()):
        output_indices[output.name] = index
    ort_result = session.run(None, {"input": sample})
    score_output = ort_result[output_indices["scores"]]
    score_array = np.asarray(score_output)
    ort_scores = score_array.ravel()
    skl_scores = model.decision_function(sample)

    diff = np.abs(ort_scores - skl_scores)
    median_diff = np.median(diff)
    ort_anomalies = ort_scores < threshold
    skl_anomalies = skl_scores < threshold
    matching_decisions = ort_anomalies == skl_anomalies
    agreement = matching_decisions.mean()

    #Assert
    assert median_diff < 1e-6
    #float32切分阈值偏差
    #float32 split threshold drift
    assert diff.max() < 0.02
    assert agreement >= 0.9999

@needs_artifacts
def test_if_onnx_metadata_matches_tuning_result():
    # Arrange
    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    system_text = SYSTEM_METRICS_PATH.read_text(encoding="utf-8")
    system = json.loads(system_text)

    #Act
    model_meta = session.get_modelmeta()
    meta = model_meta.custom_metadata_map
    feature_names = json.loads(meta["feature_names"])
    threshold = float(meta["anomaly_threshold"])
    at_060 = float(meta["score_at_confidence_060"])
    at_095 = float(meta["score_at_confidence_095"])
    inputs = session.get_inputs()
    output_names = set()
    for output in session.get_outputs():
        output_names.add(output.name)

    #Assert
    assert feature_names == FEATURE_NAMES
    assert meta["model_type"] == "IsolationForest"
    assert threshold == pytest.approx(system["selected_threshold"])
    assert at_060 == pytest.approx(threshold)
    #分数越低越异常
    #Lower score = more anomalous
    assert at_095 < at_060
    assert at_060 < 0

    assert len(inputs) == 1
    input_info = inputs[0]
    assert input_info.shape[1] == len(FEATURE_NAMES)
    assert input_info.type == "tensor(float)"
    assert output_names == {"label", "scores"}