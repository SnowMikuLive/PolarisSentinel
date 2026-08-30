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


def make_frame(**overrides) -> pd.DataFrame:
    row = {raw: 0.0 for _, raw in BASE_FEATURES}
    row.update(overrides)
    return pd.DataFrame([row])


def feature(X: np.ndarray, name: str) -> float:
    return float(X[0, FEATURE_NAMES.index(name)])


def test_schema_is_fixed():
    assert len(FEATURE_NAMES) == 20
    assert len(set(FEATURE_NAMES)) == 20
    assert FEATURE_NAMES[: len(BASE_FEATURES)] == [name for name, _ in BASE_FEATURES]
    assert FEATURE_NAMES[-len(DERIVED_FEATURES):] == DERIVED_FEATURES
    assert CLASS_NAMES == ["Benign", "BruteForce", "DoS", "PortScan"]


def test_label_mapping():
    assert set(LABEL_MAPPING.values()) == set(CLASS_NAMES)
    assert LABEL_MAPPING["BENIGN"] == "Benign"
    for label in ("DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"):
        assert LABEL_MAPPING[label] == "DoS"
    assert LABEL_MAPPING["PortScan"] == "PortScan"
    for label in ("FTP-Patator", "SSH-Patator"):
        assert LABEL_MAPPING[label] == "BruteForce"
    for label in ("DDoS", "Bot", "Infiltration", "Heartbleed"):
        assert label not in LABEL_MAPPING


def test_output_type_and_shape():
    X = build_features(make_frame())
    assert X.dtype == np.float32
    assert X.shape == (1, 20)


def test_microsecond_to_millisecond_conversion():
    X = build_features(make_frame(**{" Flow Duration": 2000.0, " Fwd IAT Mean": 500.0}))
    assert feature(X, "flow_duration_ms") == pytest.approx(2.0)
    assert feature(X, "fwd_iat_mean_ms") == pytest.approx(0.5)


def test_zero_duration_rates_are_zero():
    X = build_features(make_frame(**{
        " Flow Duration": 0.0,
        " Total Fwd Packets": 2.0,
        "Total Length of Fwd Packets": 100.0,
    }))
    assert feature(X, "flow_bytes_per_ms") == 0.0
    assert feature(X, "flow_pkts_per_ms") == 0.0


def test_derived_features():
    X = build_features(make_frame(**{
        " Flow Duration": 2000.0,          # 2 ms
        " Total Fwd Packets": 2.0,
        " Total Backward Packets": 4.0,
        "Total Length of Fwd Packets": 100.0,
        " Total Length of Bwd Packets": 300.0,
    }))
    assert feature(X, "flow_bytes_per_ms") == pytest.approx(200.0)
    assert feature(X, "flow_pkts_per_ms") == pytest.approx(3.0)
    assert feature(X, "down_up_ratio") == pytest.approx(2.0)


def test_zero_fwd_packets_ratio_is_zero():
    X = build_features(make_frame(**{" Total Backward Packets": 5.0}))
    assert feature(X, "down_up_ratio") == 0.0


def test_negative_time_values_clipped():
    X = build_features(make_frame(**{" Fwd IAT Min": -5000.0}))
    assert feature(X, "fwd_iat_min_ms") == 0.0


@needs_data
def test_prepared_arrays_are_clean():
    data = np.load(DATA_PATH)
    assert data["feature_names"].tolist() == FEATURE_NAMES
    assert data["class_names"].tolist() == CLASS_NAMES
    for split in ("train", "val", "test"):
        X, y = data[f"X_{split}"], data[f"y_{split}"]
        assert X.dtype == np.float32
        assert X.shape[1] == 20
        assert np.isfinite(X).all()
        assert y.min() >= 0 and y.max() < len(CLASS_NAMES)


@needs_data
def test_no_identical_rows_across_splits():
    data = np.load(DATA_PATH)
    hashes = {
        split: set(pd.util.hash_pandas_object(
            pd.DataFrame(data[f"X_{split}"]), index=False
        ).to_numpy())
        for split in ("train", "val", "test")
    }
    assert not hashes["train"] & hashes["val"]
    assert not hashes["train"] & hashes["test"]
    assert not hashes["val"] & hashes["test"]
