"""构建孤立森林评估用的新类攻击留出集。
Build the novelty holdout set for Isolation Forest evaluation.

随机森林四分类未包含的攻击族；分类器从未见过且无法命名，用于测试未知异常检测。
Attack families excluded from the RF's four classes — tests true unknown-anomaly detection.

输出:
- ml/data/novelty.npz  新类特征矩阵、攻击族标签、特征名
  X_novelty, groups, feature_names
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

from prepare_dataset import BASE_FEATURES, FEATURE_NAMES, FILES, LABEL_MAPPING, build_features

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT.parent / "CIC-IDS2017"
OUT_PATH = ROOT / "data" / "novelty.npz"

# 新类攻击组：不在 RF 训练范围内的标签
# Novelty groups: labels outside the RF training scope
NOVELTY_GROUPS = {
    "DDoS": lambda label: label == "DDoS",
    "Bot": lambda label: label == "Bot",
    "WebAttack": lambda label: label.startswith("Web Attack"),
    "Infiltration": lambda label: label == "Infiltration",
    "Heartbleed": lambda label: label == "Heartbleed",
}


def classify(label: str) -> str | None:
    """将原始 CIC 标签映射到新类组名；若在 RF 范围内则返回 None。
    Map a raw CIC label to a novelty group name, or None if in RF scope."""
    for group, matches in NOVELTY_GROUPS.items():
        if matches(label):
            return group
    return None


def main() -> None:
    usecols = [raw for _, raw in BASE_FEATURES] + [" Label"]
    df = pd.concat(
        [pd.read_csv(DATASET_DIR / f, usecols=usecols) for f in FILES],
        ignore_index=True,
    )

    known = set(LABEL_MAPPING)
    df["Group"] = df[" Label"].map(classify)
    unmapped = set(df.loc[df["Group"].isna(), " Label"]) - known
    if unmapped:
        raise SystemExit(f"Labels neither known nor classified as novelty: {unmapped}")

    df = df.dropna(subset=["Group"])

    negative_duration = df[" Flow Duration"] < 0
    print(f"Dropped rows with negative Flow Duration: {int(negative_duration.sum()):,}")
    df = df[~negative_duration]

    X = build_features(df)
    groups = df["Group"].to_numpy(dtype=object)

    print(f"Features ({len(FEATURE_NAMES)}): identical contract to prepared.npz")
    print("Novelty holdout composition:")
    for group, count in pd.Series(groups).value_counts().items():
        print(f"    {group:<14} {count:>8,}")
    print(f"    {'TOTAL':<14} {len(groups):>8,}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        OUT_PATH,
        X_novelty=X,
        groups=groups.astype(str),
        feature_names=np.array(FEATURE_NAMES),
    )
    print(f"Saved {OUT_PATH} ({OUT_PATH.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
