"""验证 prepare_dataset 的特征工程逻辑与 prepared.npz 数据质量。
Verify prepare_dataset feature engineering and prepared.npz data quality.

单元测试不依赖数据集文件；标记为 @needs_data 的测试需先运行 prepare_dataset.py。
Unit tests run without dataset files; @needs_data tests require prepare_dataset.py first.
"""

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
    """构造单行测试 DataFrame，可覆盖指定原始 CSV 列。
    Build a one-row test DataFrame, optionally overriding raw CSV columns."""
    row = {raw: 0.0 for _, raw in BASE_FEATURES}
    row.update(overrides)
    return pd.DataFrame([row])


def feature(X: np.ndarray, name: str) -> float:
    """按内部特征名读取 build_features 输出中的单个值。
    Read one value from build_features output by internal feature name."""
    return float(X[0, FEATURE_NAMES.index(name)])


def test_schema_is_fixed():
    """特征维度、顺序和类别列表必须与 C#/ONNX 契约一致。
    Feature count, order, and class list must match the C#/ONNX contract."""
    assert len(FEATURE_NAMES) == 20
    assert len(set(FEATURE_NAMES)) == 20
    assert FEATURE_NAMES[: len(BASE_FEATURES)] == [name for name, _ in BASE_FEATURES]
    assert FEATURE_NAMES[-len(DERIVED_FEATURES):] == DERIVED_FEATURES
    assert CLASS_NAMES == ["Benign", "BruteForce", "DoS", "PortScan"]


def test_label_mapping():
    """CIC 原始标签应正确映射到四类攻击；新类攻击不在映射表中。
    Raw CIC labels map to four attack families; novelty labels are excluded."""
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
    """build_features 应输出 (N, 20) 的 float32 矩阵。
    build_features must return an (N, 20) float32 matrix."""
    X = build_features(make_frame())
    assert X.dtype == np.float32
    assert X.shape == (1, 20)


def test_microsecond_to_millisecond_conversion():
    """CIC 时间列以微秒存储，应转换为毫秒。
    CIC time columns are stored in microseconds and must be converted to milliseconds."""
    X = build_features(make_frame(**{" Flow Duration": 2000.0, " Fwd IAT Mean": 500.0}))
    assert feature(X, "flow_duration_ms") == pytest.approx(2.0)
    assert feature(X, "fwd_iat_mean_ms") == pytest.approx(0.5)


def test_zero_duration_rates_are_zero():
    """持续时间为零时，速率特征应安全归零而非除零。
    When duration is zero, rate features must be zero rather than divide-by-zero."""
    X = build_features(make_frame(**{
        " Flow Duration": 0.0,
        " Total Fwd Packets": 2.0,
        "Total Length of Fwd Packets": 100.0,
    }))
    assert feature(X, "flow_bytes_per_ms") == 0.0
    assert feature(X, "flow_pkts_per_ms") == 0.0


def test_derived_features():
    """派生特征（字节/包速率、上下行比）应按公式正确计算。
    Derived features (byte/packet rates, down-up ratio) must match expected formulas."""
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
    """正向包数为零时，上下行比应归零。
    When forward packet count is zero, down-up ratio must be zero."""
    X = build_features(make_frame(**{" Total Backward Packets": 5.0}))
    assert feature(X, "down_up_ratio") == 0.0


def test_negative_time_values_clipped():
    """偶发的负 IAT 值应裁剪为 0，避免污染特征空间。
    Rare negative IAT values must be clipped to 0 to avoid polluting the feature space."""
    X = build_features(make_frame(**{" Fwd IAT Min": -5000.0}))
    assert feature(X, "fwd_iat_min_ms") == 0.0


@needs_data
def test_prepared_arrays_are_clean():
    """prepared.npz 各划分的 dtype、维度和有限性应符合契约。
    Each split in prepared.npz must have correct dtype, shape, and finite values."""
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
    """相同特征行不得跨 train/val/test 划分（防止记忆型过拟合）。
    Identical feature rows must not appear in more than one split."""
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
