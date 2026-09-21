#prepare_dataset特征工程测试
#Feature engineering tests for prepare_dataset.
from pathlib import Path
import numpy as np
import pandas as pd
import pytest
from prepare_dataset import (
    BASE_FEATURES,
    CLASS_NAMES,
    DERIVED_FEATURES,
    FEATURE_NAMES,
    LABEL_MAPPING,
    build_features,
)
DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "prepared.npz"
needs_data = pytest.mark.skipif(not DATA_PATH.exists(), reason="run prepare_dataset.py first")

def make_frame(**overrides):
    row = {}
    for name, raw_column in BASE_FEATURES:
        row[raw_column] = 0.0
    row.update(overrides)
    return pd.DataFrame([row])

def feature(X, name):
    column_index = FEATURE_NAMES.index(name)
    value = X[0, column_index]
    return float(value)

def test_schema_is_fixed():
    # Arrange
    expected_base_names = []
    for name, raw_column in BASE_FEATURES:
        expected_base_names.append(name)
    expected_classes = ["Benign", "BruteForce", "DoS", "PortScan"]

    # Act
    unique_names = set(FEATURE_NAMES)
    base_names = FEATURE_NAMES[:len(BASE_FEATURES)]
    derived_names = FEATURE_NAMES[-len(DERIVED_FEATURES):]

    # Assert
    assert len(FEATURE_NAMES) == 20
    assert len(unique_names) == 20
    assert base_names == expected_base_names
    assert derived_names == DERIVED_FEATURES
    assert CLASS_NAMES == expected_classes

def test_label_mapping():
    # Arrange
    dos_labels = ("DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest")
    brute_force_labels = ("FTP-Patator", "SSH-Patator")
    excluded_labels = ("DDoS", "Bot", "Infiltration", "Heartbleed")

    # Act
    mapped_classes = set(LABEL_MAPPING.values())
    expected_classes = set(CLASS_NAMES)

    # Assert
    assert mapped_classes == expected_classes
    assert LABEL_MAPPING["BENIGN"] == "Benign"
    for label in dos_labels:
        assert LABEL_MAPPING[label] == "DoS"
    assert LABEL_MAPPING["PortScan"] == "PortScan"
    for label in brute_force_labels:
        assert LABEL_MAPPING[label] == "BruteForce"
    for label in excluded_labels:
        assert label not in LABEL_MAPPING

def test_output_type_and_shape():
    # Arrange
    frame = make_frame()

    # Act
    X = build_features(frame)

    # Assert
    assert X.dtype == np.float32
    assert X.shape == (1, 20)

def test_microsecond_to_millisecond_conversion():
    # Arrange
    frame = make_frame(**{" Flow Duration": 2000.0, " Fwd IAT Mean": 500.0})

    # Act
    X = build_features(frame)
    duration_ms = feature(X, "flow_duration_ms")
    iat_mean_ms = feature(X, "fwd_iat_mean_ms")

    # Assert
    assert duration_ms == pytest.approx(2.0)
    assert iat_mean_ms == pytest.approx(0.5)

def test_zero_duration_rates_are_zero():
    # Arrange
    frame = make_frame(**{
        " Flow Duration": 0.0,
        " Total Fwd Packets": 2.0,
        "Total Length of Fwd Packets": 100.0,
    })

    # Act
    X = build_features(frame)
    bytes_per_ms = feature(X, "flow_bytes_per_ms")
    packets_per_ms = feature(X, "flow_pkts_per_ms")

    # Assert
    assert bytes_per_ms == 0.0
    assert packets_per_ms == 0.0

def test_derived_features():
    # Arrange
    frame = make_frame(**{
        " Flow Duration": 2000.0,
        " Total Fwd Packets": 2.0,
        " Total Backward Packets": 4.0,
        "Total Length of Fwd Packets": 100.0,
        " Total Length of Bwd Packets": 300.0,
    })

    # Act
    X = build_features(frame)
    bytes_per_ms = feature(X, "flow_bytes_per_ms")
    packets_per_ms = feature(X, "flow_pkts_per_ms")
    down_up_ratio = feature(X, "down_up_ratio")

    # Assert
    assert bytes_per_ms == pytest.approx(200.0)
    assert packets_per_ms == pytest.approx(3.0)
    assert down_up_ratio == pytest.approx(2.0)
def test_zero_fwd_packets_ratio_is_zero():
    
    # Arrange
    frame = make_frame(**{" Total Backward Packets": 5.0})

    # Act
    X = build_features(frame)
    down_up_ratio = feature(X, "down_up_ratio")

    # Assert
    assert down_up_ratio == 0.0

def test_negative_time_values_clipped():
    # Arrange
    frame = make_frame(**{" Fwd IAT Min": -5000.0})

    # Act
    X = build_features(frame)
    iat_min_ms = feature(X, "fwd_iat_min_ms")

    # Assert
    assert iat_min_ms == 0.0

@needs_data
def test_prepared_arrays_are_clean():
    # Arrange
    data = np.load(DATA_PATH)

    # Act
    feature_names = data["feature_names"].tolist()
    class_names = data["class_names"].tolist()

    # Assert
    assert feature_names == FEATURE_NAMES
    assert class_names == CLASS_NAMES
    for split in ("train", "val", "test"):
        X = data[f"X_{split}"]
        y = data[f"y_{split}"]
        finite_values = np.isfinite(X)
        assert X.dtype == np.float32
        assert X.shape[1] == 20
        assert finite_values.all()
        assert y.min() >= 0
        assert y.max() < len(CLASS_NAMES)

@needs_data
def test_no_identical_rows_across_splits():
    # Arrange
    data = np.load(DATA_PATH)

    # Act
    hashes = {}
    for split in ("train", "val", "test"):
        frame = pd.DataFrame(data[f"X_{split}"])
        row_hashes = pd.util.hash_pandas_object(frame, index=False)
        hash_values = row_hashes.to_numpy()
        hashes[split] = set(hash_values)
    train_val_overlap = hashes["train"].intersection(hashes["val"])
    train_test_overlap = hashes["train"].intersection(hashes["test"])
    val_test_overlap = hashes["val"].intersection(hashes["test"])

    # Assert
    assert len(train_val_overlap) == 0
    assert len(train_test_overlap) == 0
    assert len(val_test_overlap) == 0