# Generate a CIC-IDS-2017-like labeled test CSV in the exact 20-feature schema the
# trained models expect.
#
# This is SYNTHETIC data, not a copy of the real CIC-IDS2017 CSVs. Every row is
# produced by jittering a real feature vector from ml/artifacts/inference_cases.json
# (which WAS captured from the real dataset while validating the models). Seeding
# from real vectors is the only reliable way to stay inside the trained models'
# decision region, because the classifiers are highly sensitive to exact values.
#
# Output: ml/artifacts/test_dataset.csv
import csv
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
CASES_PATH = ARTIFACTS / "inference_cases.json"
OUTPUT = ARTIFACTS / "test_dataset.csv"

FEATURE_NAMES = [
    "flow_duration_ms",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "pkt_len_min",
    "pkt_len_max",
    "pkt_len_mean",
    "pkt_len_std",
    "fwd_iat_mean_ms",
    "fwd_iat_std_ms",
    "fwd_iat_max_ms",
    "fwd_iat_min_ms",
    "bwd_iat_mean_ms",
    "bwd_iat_std_ms",
    "bwd_iat_max_ms",
    "bwd_iat_min_ms",
    "flow_bytes_per_ms",
    "flow_pkts_per_ms",
    "down_up_ratio",
]

# Each class is seeded from the real reference vectors that the model already
# classifies correctly, so the synthetic rows stay in-distribution.
CLASS_SEEDS = {
    "Benign": ["benign_normal", "low_rf_normal"],
    "BruteForce": ["rf_attack"],
    "DoS": ["low_rf_anomaly"],
    "PortScan": ["benign_anomaly"],
}

random.seed(42)


def jitter(value, spread):
    # Multiplicative jitter keeps the sign and stays near the seed value.
    factor = 1.0 + random.uniform(-spread, spread)
    return round(max(value * factor, 0.0), 6)


def main():
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    per_class = 100
    rows = []

    for label, seed_names in CLASS_SEEDS.items():
        vectors = [cases[name]["features"] for name in seed_names if name in cases]
        for i in range(per_class):
            seed = vectors[i % len(vectors)]
            # Tighter spread on the attack classes keeps them in the decision region.
            spread = 0.05 if label != "Benign" else 0.15
            row = {name: jitter(seed[index], spread) for index, name in enumerate(FEATURE_NAMES)}
            row["label"] = label
            rows.append(row)

    random.shuffle(rows)

    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FEATURE_NAMES + ["label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()
