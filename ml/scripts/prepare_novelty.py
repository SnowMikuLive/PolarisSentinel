import sys
from pathlib import Path

import numpy as np
import pandas as pd

from prepare_dataset import BASE_FEATURES, FEATURE_NAMES, FILES, LABEL_MAPPING, build_features

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT.parent / "CIC-IDS2017"
OUT_PATH = ROOT / "data" / "novelty.npz"

# Attack families excluded from the Random Forest's four classes. The classifier
# has never seen them and cannot name them, which makes them a genuine held-out
# test of the Isolation Forest's unknown-anomaly detection.
NOVELTY_GROUPS = {
    "DDoS": lambda label: label == "DDoS",
    "Bot": lambda label: label == "Bot",
    "WebAttack": lambda label: label.startswith("Web Attack"),
    "Infiltration": lambda label: label == "Infiltration",
    "Heartbleed": lambda label: label == "Heartbleed",
}


def classify(label: str) -> str | None:
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
