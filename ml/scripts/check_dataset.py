import sys
from pathlib import Path

import pandas as pd

# CIC-IDS2017 labels contain U+FFFD (e.g. "Web Attack <?> Brute Force"),
# which the default GBK console codec cannot print.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DATASET_DIR = Path(__file__).resolve().parents[2] / "CIC-IDS2017"
LABEL_COLUMN = " Label"

EXPECTED_FILES = [
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
# Everything not in LABEL_MAPPING is out of scope and will be dropped.


def main() -> None:
    missing = [name for name in EXPECTED_FILES if not (DATASET_DIR / name).exists()]
    if missing:
        raise SystemExit(f"MISSING FILES: {missing}")
    print(f"All {len(EXPECTED_FILES)} expected files present in {DATASET_DIR}")
    print("=" * 72)

    reference_header: list[str] | None = None
    per_file_counts: dict[str, pd.Series] = {}

    for name in EXPECTED_FILES:
        path = DATASET_DIR / name
        header = pd.read_csv(path, nrows=0).columns.tolist()
        if reference_header is None:
            reference_header = header
        elif header != reference_header:
            raise SystemExit(f"HEADER MISMATCH in {name}")

        labels = pd.read_csv(path, usecols=[LABEL_COLUMN])[LABEL_COLUMN]
        counts = labels.value_counts()
        per_file_counts[name] = counts

        print(f"\n{name}  (rows: {len(labels):,})")
        for label, count in counts.items():
            marker = "" if label in LABEL_MAPPING else "  [OUT OF SCOPE -> drop]"
            print(f"    {label!r}: {count:,}{marker}")

    print("\n" + "=" * 72)
    print(f"Header check: all files share the same {len(reference_header)} columns")

    total = pd.concat(per_file_counts.values()).groupby(level=0).sum()
    mapped = (
        total.rename(index=LABEL_MAPPING)
        .groupby(level=0)
        .sum()
        .loc[lambda s: s.index.isin(set(LABEL_MAPPING.values()))]
        .sort_values(ascending=False)
    )
    dropped = total[~total.index.isin(LABEL_MAPPING)].sort_values(ascending=False)

    print("\nMerged class distribution under contract mapping:")
    for label, count in mapped.items():
        print(f"    {label}: {count:,}  ({count / mapped.sum():.2%} of in-scope rows)")
    print(f"\nOut-of-scope rows to be dropped: {dropped.sum():,}")
    for label, count in dropped.items():
        print(f"    {label!r}: {count:,}")
    print(f"\nTotal rows across all files: {total.sum():,}")


if __name__ == "__main__":
    main()
