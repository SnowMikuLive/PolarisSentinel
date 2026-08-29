import sys
from pathlib import Path

import numpy as np
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
    " Destination Port",
    " Flow Duration",
    " Total Fwd Packets",
    " Total Backward Packets",
    "Total Length of Fwd Packets",
    " Total Length of Bwd Packets",
    " SYN Flag Count",
    "FIN Flag Count",
    " RST Flag Count",
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
CLASSES = ["Benign", "DoS", "PortScan", "BruteForce"]

MIN_PACKETS = 3  # PolicySettings.PreFilterMinPackets


def main() -> None:
    df = pd.concat(
        [pd.read_csv(DATASET_DIR / f, usecols=USECOLS) for f in FILES],
        ignore_index=True,
    )
    df.columns = [c.strip() for c in df.columns]
    df["Class"] = df["Label"].map(LABEL_MAPPING)
    df = df.dropna(subset=["Class"])

    fwd = df["Total Fwd Packets"].to_numpy(np.float64)
    bwd = df["Total Backward Packets"].to_numpy(np.float64)
    fwd_bytes = df["Total Length of Fwd Packets"].to_numpy(np.float64)
    bwd_bytes = df["Total Length of Bwd Packets"].to_numpy(np.float64)
    duration_ms = df["Flow Duration"].to_numpy(np.float64) / 1e3
    syn = df["SYN Flag Count"].to_numpy(np.float64)
    fin = df["FIN Flag Count"].to_numpy(np.float64)
    rst = df["RST Flag Count"].to_numpy(np.float64)
    dst_port = df["Destination Port"].to_numpy(np.float64)

    # FlowRecord.DownUpRatio: FwdBytes / BwdBytes with MaxValue / 1.0 fallbacks
    ratio = np.where(
        bwd_bytes > 0,
        np.divide(fwd_bytes, bwd_bytes, out=np.ones_like(fwd_bytes), where=bwd_bytes > 0),
        np.where(fwd_bytes > 0, np.inf, 1.0),
    )

    r1 = (fwd + bwd) < MIN_PACKETS
    r2 = duration_ms < 100.0
    r3 = (fwd == 0) | (bwd == 0)
    r4 = (
        np.isin(dst_port, (80, 443))
        & (fwd > 5) & (bwd > 5)
        & (syn <= 1) & (rst == 0) & (fin <= 2)
        & (ratio > 0.1) & (ratio < 10)
    )
    r5 = (fwd > 0) & (bwd > 0) & (duration_ms > 1000.0) & (syn <= 1)

    # live PreFilter short-circuits in rule order
    skip = [
        r1,
        ~r1 & r2,
        ~r1 & ~r2 & r3,
        ~r1 & ~r2 & ~r3 & r4,
        ~r1 & ~r2 & ~r3 & ~r4 & r5,
    ]
    reach = ~(r1 | r2 | r3 | r4 | r5)

    print("NOTE: dataset flag counts are 0/1 artefacts of the buggy CICFlowMeter build,")
    print("so rules 4-5 (SYN/RST/FIN conditions) are approximations of live behaviour.\n")

    header = (f"{'Class':<12} {'rows':>10} {'r1<3pkt':>9} {'r2<100ms':>9} "
              f"{'r3 unidir':>10} {'r4 web':>8} {'r5 2way':>8} {'reach model':>12}")
    print(header)
    print("-" * len(header))
    for cls in CLASSES:
        mask = (df["Class"] == cls).to_numpy()
        n = int(mask.sum())
        cells = "".join(f"{(m & mask).sum() / n:>{w}.2%}"
                        for m, w in zip(skip, (9, 9, 10, 8, 8)))
        print(f"{cls:<12} {n:>10,}{cells}{(reach & mask).sum() / n:>12.2%}")

    print("\nAttack flows silently allowed (never reach the model):")
    for cls in CLASSES:
        if cls == "Benign":
            continue
        mask = (df["Class"] == cls).to_numpy()
        allowed = int((~reach & mask).sum())
        print(f"    {cls:<12} {allowed:,} of {int(mask.sum()):,} ({allowed / mask.sum():.2%})")


if __name__ == "__main__":
    main()
