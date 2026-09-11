# IF 变体对比。输出: if_*.joblib, metrics_if_variants.json
# Compare IF variants. Outputs: if_*.joblib, metrics_if_variants.json

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import PowerTransformer, QuantileTransformer

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
NOVELTY_PATH = ROOT / "data" / "novelty.npz"
METRICS_PATH = ROOT / "artifacts" / "metrics_if_variants.json"
MODEL_DIR = ROOT / "data"

SEED = 42
BENIGN = 0
FIT_ROWS = 300_000
FPR_BUDGETS = [0.002, 0.005, 0.007, 0.01]
# 排序主预算
# primary ranking budget
REPORT_BUDGET = 0.007
MAX_SAMPLES_GRID = [256, 4096, 32768]


def build_transforms():
    return {
        "raw": None,
        "quantile": QuantileTransformer(
            output_distribution="uniform", n_quantiles=1000,
            subsample=200_000, random_state=SEED),
        "power": PowerTransformer(method="yeo-johnson"),
    }


def main():
    data = np.load(DATA_PATH)
    novelty = np.load(NOVELTY_PATH, allow_pickle=False)

    X_train, y_train = data["X_train"], data["y_train"]
    X_val, y_val = data["X_val"], data["y_val"]
    class_names = data["class_names"].tolist()

    X_novelty = novelty["X_novelty"]
    novelty_groups = novelty["groups"]
    group_names = sorted(set(novelty_groups.tolist()))

    benign_train = X_train[y_train == BENIGN]
    benign_val = X_val[y_val == BENIGN]
    known_val = {}
    for i, name in enumerate(class_names):
        if i != BENIGN:
            known_val[name] = X_val[y_val == i]

    rng = np.random.default_rng(SEED)
    fit_idx = rng.choice(len(benign_train), size=min(FIT_ROWS, len(benign_train)), replace=False)
    X_fit = benign_train[fit_idx]

    print(f"Benign train pool : {len(benign_train):,} rows")
    print(f"Fit subsample     : {len(X_fit):,} rows")
    print(f"Benign val        : {len(benign_val):,} rows")
    print(f"Novelty holdout   : {len(X_novelty):,} rows ({', '.join(group_names)})")
    print()

    results = []
    for transform_name, transform in build_transforms().items():
        if transform is None:
            fit_seconds = 0.0
            T_fit = X_fit
            T_benign = benign_val
            T_novelty = X_novelty
            T_known = known_val
        else:
            start = time.perf_counter()
            transform.fit(X_fit)
            fit_seconds = time.perf_counter() - start
            T_fit = transform.transform(X_fit)
            T_benign = transform.transform(benign_val)
            T_novelty = transform.transform(X_novelty)
            T_known = {}
            for name, rows in known_val.items():
                T_known[name] = transform.transform(rows)
        print(f"=== transform: {transform_name} (fit {fit_seconds:.0f}s) ===")

        for max_samples in MAX_SAMPLES_GRID:
            forest = IsolationForest(
                n_estimators=200, max_samples=max_samples,
                random_state=SEED, n_jobs=-1,
            )
            start = time.perf_counter()
            forest.fit(T_fit)
            forest_seconds = time.perf_counter() - start

            benign_scores = forest.decision_function(T_benign)
            novelty_scores = forest.decision_function(T_novelty)

            auc_labels = np.r_[np.zeros(len(benign_scores)), np.ones(len(novelty_scores))]
            # 取反使新类为正类 / Flip scores for AUC.
            auc_scores = np.r_[-benign_scores, -novelty_scores]
            auc = float(roc_auc_score(auc_labels, auc_scores))

            entry = {
                "transform": transform_name,
                "max_samples": max_samples,
                "fit_seconds": round(forest_seconds, 1),
                "novelty_auc": auc,
                "budgets": {},
            }
            for budget in FPR_BUDGETS:
                threshold = float(np.quantile(benign_scores, budget))
                per_group = {}
                for group in group_names:
                    group_scores = novelty_scores[novelty_groups == group]
                    per_group[group] = float((group_scores < threshold).mean())
                entry["budgets"][f"{budget:.3f}"] = {
                    "threshold": threshold,
                    "benign_fpr": float((benign_scores < threshold).mean()),
                    "novelty_overall": float((novelty_scores < threshold).mean()),
                    "per_group": per_group,
                }

            report = entry["budgets"][f"{REPORT_BUDGET:.3f}"]
            known_attack_flag_rate = {}
            for name, rows in T_known.items():
                scores = forest.decision_function(rows)
                known_attack_flag_rate[name] = float((scores < report["threshold"]).mean())
            entry["known_attack_flag_rate"] = known_attack_flag_rate

            detail = ", ".join(f"{g} {v:.1%}" for g, v in report["per_group"].items())
            known = ", ".join(f"{k} {v:.1%}" for k, v in entry["known_attack_flag_rate"].items())
            print(f"  max_samples {max_samples:>6} ({forest_seconds:>4.0f}s) | "
                  f"AUC {auc:.4f} | novelty@{REPORT_BUDGET:.1%} "
                  f"{report['novelty_overall']:>6.1%} | {detail}")
            print(f"{'':>25}   known-class flagged: {known}")

            if transform is None:
                model = forest
            else:
                model = Pipeline([("scale", transform), ("iforest", forest)])
            joblib.dump(model, MODEL_DIR / f"if_{transform_name}_{max_samples}.joblib", compress=3)
            results.append(entry)
        print()

    ranked = sorted(results, key=lambda r: -r["budgets"][f"{REPORT_BUDGET:.3f}"]["novelty_overall"])
    print(f"Ranked by novelty detection at {REPORT_BUDGET:.1%} benign FPR budget:")
    for entry in ranked[:5]:
        detected = entry["budgets"][f"{REPORT_BUDGET:.3f}"]["novelty_overall"]
        print(f"    {entry['transform']:<9} max_samples {entry['max_samples']:>6} | "
              f"{detected:>6.1%} | AUC {entry['novelty_auc']:.4f}")

    metrics = {
        "seed": SEED,
        "fit_rows": int(len(X_fit)),
        "benign_val_rows": int(len(benign_val)),
        "novelty_rows": int(len(X_novelty)),
        "report_budget": REPORT_BUDGET,
        "results": results,
        "best": {"transform": ranked[0]["transform"], "max_samples": ranked[0]["max_samples"]},
    }
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"\nSaved {METRICS_PATH}")


if __name__ == "__main__":
    main()
