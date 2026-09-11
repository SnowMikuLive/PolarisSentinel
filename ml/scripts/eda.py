# CIC-IDS2017 探索性分析。仅打印，不写文件
# EDA on raw CIC-IDS2017 CSVs. Prints only, no files written.

import sys
from pathlib import Path

import numpy as np
import pandas as pd

# GBK 控制台兼容
# GBK console compat
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATASET_DIR = Path(__file__).resolve().parents[2] / "CIC-IDS2017"

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
CLASSES = ["Benign", "DoS", "PortScan", "BruteForce"]

# 列名含前导空格
# Leading spaces preserved
BASE_COLS = [
    " Flow Duration",
    " Total Fwd Packets",
    " Total Backward Packets",
    "Total Length of Fwd Packets",
    " Total Length of Bwd Packets",
    " Min Packet Length",
    " Max Packet Length",
    " Packet Length Mean",
    " Packet Length Std",
    " Fwd IAT Mean",
    " Fwd IAT Std",
    " Fwd IAT Max",
    " Fwd IAT Min",
    " Bwd IAT Mean",
    " Bwd IAT Std",
    " Bwd IAT Max",
    " Bwd IAT Min",
]
FLAG_COLS = [
    "FIN Flag Count",
    " SYN Flag Count",
    " RST Flag Count",
    " PSH Flag Count",
    " ACK Flag Count",
]
TIME_COLS = [
    " Flow Duration",
    " Fwd IAT Mean", " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min",
    " Bwd IAT Mean", " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min",
]


def main():
    usecols = BASE_COLS + FLAG_COLS + [" Label"]
    frames = []
    for file_name in FILES:
        frame = pd.read_csv(DATASET_DIR / file_name, usecols=usecols)
        frames.append(frame)
    df = pd.concat(frames, ignore_index=True)
    df["Class"] = df[" Label"].map(LABEL_MAPPING)
    df = df.dropna(subset=["Class"])
    print(f"In-scope rows: {len(df):,}\n")

    print("=== 1. Column quality (NaN / Inf / negative) ===")
    header = f"{'column':<32} {'NaN':>8} {'+/-Inf':>8} {'negative':>10}"
    print(header)
    print("-" * len(header))
    for col in BASE_COLS + FLAG_COLS:
        vals = df[col]
        n_nan = int(vals.isna().sum())
        n_inf = int(np.isinf(vals).sum())
        n_neg = int((vals < 0).sum())
        if n_nan or n_inf or n_neg or col in TIME_COLS[:1]:
            print(f"{col.strip():<32} {n_nan:>8,} {n_inf:>8,} {n_neg:>10,}")
    print("(columns not listed are fully clean)\n")

    neg_dur = df[df[" Flow Duration"] < 0]
    if len(neg_dur):
        print(f"Rows with negative Flow Duration: {len(neg_dur):,} "
              f"(classes: {neg_dur['Class'].value_counts().to_dict()})\n")

    # 已舍弃 TCP flags
    # dropped from 20-D schema
    print("=== 2. Flag column reliability per class ===")
    for col in FLAG_COLS:
        parts = []
        for cls in CLASSES:
            class_values = df.loc[df["Class"] == cls, col]
            vc = class_values.value_counts().sort_index()
            top_values = []
            for value, count in vc.head(4).items():
                top_values.append(f"{int(value)}:{count:,}")
            top = ", ".join(top_values)
            parts.append(f"{cls} [{top}]")
        print(f"{col.strip():<16} " + " | ".join(parts))
    print()

    # 动机：按组划分
    # motivates group split
    print("=== 3. Duplicate feature rows (on base columns) ===")
    dup_mask = df.duplicated(subset=BASE_COLS, keep="first")
    for cls in CLASSES:
        cls_mask = df["Class"] == cls
        rate = dup_mask[cls_mask].mean()
        print(f"    {cls:<12} {rate:.2%} of {int(cls_mask.sum()):,} rows")
    print()

    print("=== 4. Per-class separation snapshot (median / p95) ===")
    dur_ms = df[" Flow Duration"] / 1e3
    total_pkts = df[" Total Fwd Packets"] + df[" Total Backward Packets"]
    total_bytes = df["Total Length of Fwd Packets"] + df[" Total Length of Bwd Packets"]
    bytes_per_ms = np.where(dur_ms > 0, total_bytes / dur_ms, 0.0)
    snapshot = pd.DataFrame({
        "Class": df["Class"],
        "dur_ms": dur_ms,
        "pkts": total_pkts,
        "bytes_per_ms": bytes_per_ms,
        "pkt_len_mean": df[" Packet Length Mean"],
        "fwd_iat_mean_ms": df[" Fwd IAT Mean"] / 1e3,
    })
    stats = snapshot.groupby("Class").quantile([0.5, 0.95]).round(2)
    print(stats.to_string())


if __name__ == "__main__":
    main()
