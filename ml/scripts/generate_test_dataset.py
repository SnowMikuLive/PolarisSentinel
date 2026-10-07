#基于inference_cases.json参考向量生成含20个特征的合成带标签CSV,并非真实CIC-IDS2017数据。
#Generate a synthetic labeled CSV with 20 features from inference_cases.json reference vectors,not real CIC-IDS2017 data.
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
#按指定类别映射选取参考向量。
#Select reference vectors using the configured class mapping.
CLASS_SEEDS = {
    "Benign": ["benign_normal", "low_rf_normal"],
    "BruteForce": ["rf_attack"],
    "DoS": ["low_rf_anomaly"],
    "PortScan": ["benign_anomaly"],
}
random.seed(42)
def jitter(value, spread):
    #施加乘法扰动,将负值截为0并保留6位小数。
    #Apply multiplicative jitter,clip negative values to zero and round to six decimals.
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
            #攻击类使用更小的扰动范围,以减少偏离参考向量。
            #Use a smaller jitter range for attack classes to limit deviation from reference vectors.
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