import sys
from pathlib import Path

import pandas as pd

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

USECOLS = [
    " Total Fwd Packets",
    " Total Backward Packets",
    " Flow Duration",
    " SYN Flag Count",
    " Label",
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

MIN_PACKETS = 3  # PolicySettings.PreFilterMinPackets


def main() -> None:
    frames = [pd.read_csv(DATASET_DIR / name, usecols=USECOLS) for name in FILES]
    df = pd.concat(frames, ignore_index=True)
    df.columns = [c.strip() for c in df.columns]

    df["Class"] = df["Label"].map(LABEL_MAPPING)
    df = df.dropna(subset=["Class"])

    fwd = df["Total Fwd Packets"]
    bwd = df["Total Backward Packets"]
    duration_ms = df["Flow Duration"] / 1e3  # dataset stores microseconds
    syn = df["SYN Flag Count"]

    rule1_skip = (fwd + bwd) < MIN_PACKETS
    # live PreFilter rule 2: DurationSeconds > 1.0
    rule2_skip = (fwd > 0) & (bwd > 0) & (duration_ms > 1000.0) & (syn <= 1)
    reaches_model = ~rule1_skip & ~rule2_skip

    print("SYN Flag Count distribution per class (semantics check, OI-7):")
    for cls in ["Benign", "DoS", "PortScan", "BruteForce"]:
        counts = syn[df["Class"] == cls].value_counts().sort_index()
        shown = ", ".join(f"{int(v)}: {c:,}" for v, c in counts.head(6).items())
        print(f"    {cls:<12} {shown}")

    print()
    header = (
        f"{'Class':<12} {'rows':>10} {'rule1 skip':>12} {'rule2 skip*':>12} "
        f"{'reach model':>12} {'silently allowed':>17}"
    )
    print(header)
    print("-" * len(header))
    for cls in ["Benign", "DoS", "PortScan", "BruteForce"]:
        mask = df["Class"] == cls
        n = int(mask.sum())
        r1 = int((mask & rule1_skip).sum())
        # rule 2 evaluated on flows that survived rule 1 (live order of checks)
        r2 = int((mask & ~rule1_skip & rule2_skip).sum())
        reach = int((mask & reaches_model).sum())
        allowed = r1 + r2
        print(
            f"{cls:<12} {n:>10,} {r1 / n:>11.2%} {r2 / n:>11.2%} "
            f"{reach / n:>11.2%} {allowed:>13,} rows"
        )
    print("\n* rule2 skip = share of the WHOLE class (already excluding rule-1 rows).")
    print("  For attack classes, every skipped row is an attack flow the system")
    print("  would allow without AI inspection.")


if __name__ == "__main__":
    main()
