import json
import sys
from pathlib import Path

import numpy as np

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
OUT_PATH = ROOT.parent / "PolarisSentinel" / "DemoData" / "demo_flows.json"
SEED = 42

# (class, count) segments: mostly-benign stream with three attack bursts, twice
SEGMENTS = [
    ("Benign", 10), ("DoS", 6), ("Benign", 8), ("PortScan", 6),
    ("Benign", 8), ("BruteForce", 5), ("Benign", 10), ("DoS", 6),
    ("Benign", 8), ("PortScan", 6), ("Benign", 8), ("BruteForce", 5),
    ("Benign", 10),
]

SERVER_IP = "192.168.10.50"
ATTACKER_IP = {"DoS": "203.0.113.66", "PortScan": "198.51.100.7", "BruteForce": "203.0.113.99"}
BENIGN_CLIENTS = [f"192.168.10.{n}" for n in (11, 12, 14, 17, 23, 31)]
BENIGN_PORTS = [443, 443, 80, 53, 3389]
BRUTEFORCE_PORTS = [22, 21]


def main() -> None:
    data = np.load(DATA_PATH)
    X_test, y_test = data["X_test"], data["y_test"]
    class_names = data["class_names"].tolist()

    rng = np.random.default_rng(SEED)
    pools = {}
    for idx, name in enumerate(class_names):
        rows = np.flatnonzero(y_test == idx)
        needed = sum(count for cls, count in SEGMENTS if cls == name)
        pools[name] = iter(rng.choice(rows, size=needed, replace=False))

    flows = []
    scan_port = 1
    for cls, count in SEGMENTS:
        for _ in range(count):
            row = X_test[next(pools[cls])]
            if cls == "Benign":
                src = BENIGN_CLIENTS[rng.integers(len(BENIGN_CLIENTS))]
                dst_port = int(BENIGN_PORTS[rng.integers(len(BENIGN_PORTS))])
                protocol = 17 if dst_port == 53 else 6
            else:
                src = ATTACKER_IP[cls]
                protocol = 6
                if cls == "PortScan":
                    scan_port += int(rng.integers(1, 400))
                    dst_port = scan_port
                elif cls == "BruteForce":
                    dst_port = int(BRUTEFORCE_PORTS[rng.integers(len(BRUTEFORCE_PORTS))])
                else:
                    dst_port = 80
            flows.append({
                "features": [round(float(v), 6) for v in row],
                "sourceIp": src,
                "sourcePort": int(rng.integers(49152, 65535)),
                "destinationIp": SERVER_IP,
                "destinationPort": dst_port,
                "protocol": protocol,
                "trueLabel": cls,
            })

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(flows, indent=1), encoding="utf-8")
    counts = {cls: sum(1 for f in flows if f["trueLabel"] == cls) for cls in class_names}
    print(f"Wrote {len(flows)} flows to {OUT_PATH}")
    print(f"Composition: {counts}")


if __name__ == "__main__":
    main()
