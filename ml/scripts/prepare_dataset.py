"""加载 CIC-IDS2017 CSV，构建 20 维特征，划分 train/val/test。
Load CIC-IDS2017 CSVs, build 20-D features, and split into train/val/test.

采用按组划分，避免相同特征行泄漏到不同集合。
Uses group-aware splitting so identical feature rows never cross splits.

输出:
- ml/data/prepared.npz  特征矩阵、标签及 schema 元数据
  feature matrices, labels, and schema metadata
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT.parent / "CIC-IDS2017"
OUT_PATH = ROOT / "data" / "prepared.npz"
SEED = 42

FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

LABEL_MAPPING = {
    "BENIGN": "Benign",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
}
CLASS_NAMES = ["Benign", "BruteForce", "DoS", "PortScan"]

# 来自 CIC-IDS2017 的 17 个基础特征 (internal_name, raw_csv_column)
# 17 base features from CIC-IDS2017 (internal_name, raw_csv_column)
BASE_FEATURES = [
    ("flow_duration_ms", " Flow Duration"),
    ("total_fwd_packets", " Total Fwd Packets"),
    ("total_bwd_packets", " Total Backward Packets"),
    ("total_fwd_bytes", "Total Length of Fwd Packets"),
    ("total_bwd_bytes", " Total Length of Bwd Packets"),
    ("pkt_len_min", " Min Packet Length"),
    ("pkt_len_max", " Max Packet Length"),
    ("pkt_len_mean", " Packet Length Mean"),
    ("pkt_len_std", " Packet Length Std"),
    ("fwd_iat_mean_ms", " Fwd IAT Mean"),
    ("fwd_iat_std_ms", " Fwd IAT Std"),
    ("fwd_iat_max_ms", " Fwd IAT Max"),
    ("fwd_iat_min_ms", " Fwd IAT Min"),
    ("bwd_iat_mean_ms", " Bwd IAT Mean"),
    ("bwd_iat_std_ms", " Bwd IAT Std"),
    ("bwd_iat_max_ms", " Bwd IAT Max"),
    ("bwd_iat_min_ms", " Bwd IAT Min"),
]
# 3 个派生速率/比率特征，在训练阶段计算
# 3 derived rate/ratio features computed at training time
DERIVED_FEATURES = ["flow_bytes_per_ms", "flow_pkts_per_ms", "down_up_ratio"]
FEATURE_NAMES = [name for name, _ in BASE_FEATURES] + DERIVED_FEATURES


def build_features(df: pd.DataFrame) -> np.ndarray:
    """将原始 CSV 列转换为 20 维 float32 特征矩阵。
    Convert raw CSV columns to the 20-D float32 feature matrix."""
    cols: dict[str, np.ndarray] = {}
    for name, raw in BASE_FEATURES:
        values = df[raw].to_numpy(dtype=np.float64)
        if name.endswith("_ms"):
            values = values / 1e3  # CIC 以微秒存储，此处转为毫秒
                                    # CIC stores microseconds; we use milliseconds
        cols[name] = np.maximum(values, 0.0)  # 裁剪偶发的负 IAT 异常值
                                               # clip rare negative IAT artefacts

    duration = cols["flow_duration_ms"]
    fwd_pkts = cols["total_fwd_packets"]
    bwd_pkts = cols["total_bwd_packets"]
    total_bytes = cols["total_fwd_bytes"] + cols["total_bwd_bytes"]

    cols["flow_bytes_per_ms"] = np.divide(
        total_bytes, duration, out=np.zeros_like(duration), where=duration > 0
    )
    cols["flow_pkts_per_ms"] = np.divide(
        fwd_pkts + bwd_pkts, duration, out=np.zeros_like(duration), where=duration > 0
    )
    cols["down_up_ratio"] = np.divide(
        bwd_pkts, fwd_pkts, out=np.zeros_like(fwd_pkts), where=fwd_pkts > 0
    )

    return np.column_stack([cols[name] for name in FEATURE_NAMES]).astype(np.float32)


def print_split(name: str, y: np.ndarray) -> None:
    """打印某个划分集的行数及各类别分布。
    Print row count and per-class distribution for one split."""
    counts = np.bincount(y, minlength=len(CLASS_NAMES))
    dist = ", ".join(f"{cls}: {n:,}" for cls, n in zip(CLASS_NAMES, counts))
    print(f"    {name:<6} {len(y):>10,} rows | {dist}")


def main() -> None:
    usecols = [raw for _, raw in BASE_FEATURES] + [" Label"]
    df = pd.concat(
        [pd.read_csv(DATASET_DIR / f, usecols=usecols) for f in FILES],
        ignore_index=True,
    )
    df["Class"] = df[" Label"].map(LABEL_MAPPING)
    df = df.dropna(subset=["Class"])

    negative_duration = df[" Flow Duration"] < 0
    print(f"Dropped rows with negative Flow Duration: {int(negative_duration.sum()):,}")
    df = df[~negative_duration]

    X = build_features(df)
    class_index = {cls: i for i, cls in enumerate(CLASS_NAMES)}
    y = df["Class"].map(class_index).to_numpy(dtype=np.int8)

    # 相同特征行不得跨集合（PortScan 约 99% 重复，随机划分只会测记忆能力）
    # Identical feature rows must not straddle splits (PortScan is ~99% duplicates)
    groups = pd.util.hash_pandas_object(pd.DataFrame(X), index=False).to_numpy()

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
    train_idx, rest_idx = next(splitter.split(X, y, groups))
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED)
    val_rel, test_rel = next(splitter.split(X[rest_idx], y[rest_idx], groups[rest_idx]))
    val_idx, test_idx = rest_idx[val_rel], rest_idx[test_rel]

    for a, b in [(train_idx, val_idx), (train_idx, test_idx), (val_idx, test_idx)]:
        assert not set(groups[a]) & set(groups[b]), "duplicate rows leak across splits"

    print(f"Features ({len(FEATURE_NAMES)}): {', '.join(FEATURE_NAMES)}")
    print("Split summary (group-aware, no identical row crosses splits):")
    print_split("train", y[train_idx])
    print_split("val", y[val_idx])
    print_split("test", y[test_idx])

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        OUT_PATH,
        X_train=X[train_idx], y_train=y[train_idx],
        X_val=X[val_idx], y_val=y[val_idx],
        X_test=X[test_idx], y_test=y[test_idx],
        feature_names=np.array(FEATURE_NAMES),
        class_names=np.array(CLASS_NAMES),
    )
    print(f"Saved {OUT_PATH} ({OUT_PATH.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
