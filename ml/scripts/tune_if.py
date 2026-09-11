# 为 RF 未告警的流量调优 IF。输出: if_winner.joblib, metrics_if_system.json
# Tune IF for flows without an RF alert. Outputs: if_winner.joblib, metrics_if_system.json

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import PowerTransformer

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
NOVELTY_PATH = ROOT / "data" / "novelty.npz"
RF_PATH = ROOT / "data" / "rf_baseline.joblib"
METRICS_PATH = ROOT / "artifacts" / "metrics_if_system.json"
WINNER_PATH = ROOT / "data" / "if_winner.joblib"

SEED = 42
BENIGN = 0
FIT_ROWS = 300_000
# RF 告警的最低置信度
# Minimum confidence for an RF alert
RF_CONFIDENCE_THRESHOLD = 0.60
TOTAL_FPR_BUDGET = 0.010
SELECTED_IF_BUDGET = 0.001
GRID = [(32768, 100), (32768, 200), (65536, 100), (65536, 200), (131072, 100)]


# RF 判为攻击且达到告警阈值的样本
# RF attack predictions that meet the confidence threshold.
def rf_alerts(rf, X, class_names):
    proba = rf.predict_proba(X)
    pred = proba.argmax(axis=1)
    conf = proba.max(axis=1)
    return (pred != BENIGN) & (conf >= RF_CONFIDENCE_THRESHOLD)


def main():
    data = np.load(DATA_PATH)
    novelty = np.load(NOVELTY_PATH, allow_pickle=False)
    rf = joblib.load(RF_PATH)

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

    print("Fitting PowerTransformer (winner of the 9/7 transform comparison)...")
    transform = PowerTransformer(method="yeo-johnson")
    transform.fit(X_fit)
    T_fit = transform.transform(X_fit)
    T_benign = transform.transform(benign_val)
    T_novelty = transform.transform(X_novelty)
    T_known = {}
    for name, rows in known_val.items():
        T_known[name] = transform.transform(rows)

    print("Scoring the Random Forest once (defines what Isolation Forest ever sees)...")
    benign_rf_alert = rf_alerts(rf, benign_val, class_names)
    novelty_rf_alert = rf_alerts(rf, X_novelty, class_names)
    known_rf_alert = {}
    for name, rows in known_val.items():
        known_rf_alert[name] = rf_alerts(rf, rows, class_names)

    rf_fpr = float(benign_rf_alert.mean())
    if_budget = TOTAL_FPR_BUDGET - rf_fpr
    print(f"\nRandom Forest benign FPR : {rf_fpr:.4%}")
    print(f"Remaining budget for IF  : {if_budget:.4%} of all benign flows")
    print(f"Novelty already caught by RF (named as a known class): "
          f"{novelty_rf_alert.mean():.2%}")
    for group in group_names:
        mask = novelty_groups == group
        print(f"    {group:<14} {novelty_rf_alert[mask].mean():>6.1%}")
    print()

    results = []
    for max_samples, n_estimators in GRID:
        forest = IsolationForest(
            n_estimators=n_estimators, max_samples=max_samples,
            random_state=SEED, n_jobs=-1,
        )
        start = time.perf_counter()
        forest.fit(T_fit)
        fit_seconds = time.perf_counter() - start

        s_benign = forest.decision_function(T_benign)
        s_novelty = forest.decision_function(T_novelty)

        unseen = ~benign_rf_alert
        quantile_level = if_budget * len(benign_val) / unseen.sum()
        # IF 只补充 RF 未告警的样本
        # IF adds alerts only where RF did not alert
        threshold = float(np.quantile(s_benign[unseen], quantile_level))

        if_extra_fpr = float((unseen & (s_benign < threshold)).mean())
        system_fpr = rf_fpr + if_extra_fpr

        if_catch = ~novelty_rf_alert & (s_novelty < threshold)
        combined = novelty_rf_alert | if_catch

        per_group = {}
        for group in group_names:
            group_mask = novelty_groups == group
            per_group[group] = {
                "rf": float(novelty_rf_alert[group_mask].mean()),
                "if": float(if_catch[group_mask].mean()),
                "combined": float(combined[group_mask].mean()),
            }

        known_rescue = {}
        for cls, rows in T_known.items():
            missed = ~known_rf_alert[cls]
            scores = forest.decision_function(rows)
            if_rescue = missed & (scores < threshold)
            combined_known = known_rf_alert[cls] | if_rescue
            known_rescue[cls] = {
                "rf": float(known_rf_alert[cls].mean()),
                "combined": float(combined_known.mean()),
            }

        model = Pipeline([("scale", transform), ("iforest", forest)])
        tmp = ROOT / "data" / f"_probe_if_{max_samples}_{n_estimators}.joblib"
        joblib.dump(model, tmp, compress=3)
        size_mb = tmp.stat().st_size / 1e6

        entry = {
            "max_samples": max_samples,
            "n_estimators": n_estimators,
            "fit_seconds": round(fit_seconds, 1),
            "joblib_mb": round(size_mb, 1),
            "threshold": threshold,
            "if_extra_fpr": if_extra_fpr,
            "system_fpr": system_fpr,
            "novelty": {
                "rf_only": float(novelty_rf_alert.mean()),
                "if_added": float(if_catch.mean()),
                "combined": float(combined.mean()),
                "per_group": per_group,
            },
            "known_attacks": known_rescue,
        }
        results.append(entry)

        print(f"max_samples {max_samples:>6} x {n_estimators:>3} trees "
              f"({fit_seconds:>4.0f}s, {size_mb:>5.1f} MB joblib)")
        print(f"    system benign FPR {system_fpr:.4%} "
              f"(RF {rf_fpr:.4%} + IF {if_extra_fpr:.4%})")
        print(f"    novelty detected  {combined.mean():>6.1%} "
              f"(RF alone {novelty_rf_alert.mean():.1%}, IF adds {if_catch.mean():.1%})")
        group_details = []
        for group in group_names:
            group_details.append(f"{group} {per_group[group]['combined']:.0%}")
        print("    " + ", ".join(group_details))
        METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
        METRICS_PATH.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")

    best = max(results, key=lambda r: r["novelty"]["combined"] - 0.02 * r["joblib_mb"])
    print(f"\nSelected: max_samples {best['max_samples']} x {best['n_estimators']} trees "
          f"({best['joblib_mb']} MB)")

    forest = IsolationForest(
        n_estimators=best["n_estimators"], max_samples=best["max_samples"],
        random_state=SEED, n_jobs=-1,
    )
    forest.fit(T_fit)
    s_benign = forest.decision_function(T_benign)

    # 对比 IF 先筛选再交给 RF 的结果
    # Compare using IF to filter flows before RF
    gate_threshold = float(np.quantile(s_benign, TOTAL_FPR_BUDGET))
    print(f"\nArchitecture comparison at a {TOTAL_FPR_BUDGET:.0%} benign FPR budget")
    print(f"{'class':<12} {'parallel (RF sees all)':>24} {'gate (IF filters first)':>26}")
    for cls, rows in T_known.items():
        gate_pass = forest.decision_function(rows) < gate_threshold
        gate_detect = float((gate_pass & known_rf_alert[cls]).mean())
        print(f"{cls:<12} {known_rf_alert[cls].mean():>23.1%} {gate_detect:>25.1%}")

    unseen = ~benign_rf_alert
    s_novelty = forest.decision_function(T_novelty)
    print(f"\n{'IF budget':>10} {'system FPR':>11} {'novelty detected':>17} {'IF adds':>9}")
    sweep = {}
    for budget in (0.0005, SELECTED_IF_BUDGET, 0.002, 0.005, if_budget):
        level = budget * len(benign_val) / unseen.sum()
        thr = float(np.quantile(s_benign[unseen], level))
        if_added = ~novelty_rf_alert & (s_novelty < thr)
        added = float(if_added.mean())
        combined_rate = float((novelty_rf_alert | if_added).mean())
        sweep[f"{budget:.4f}"] = {
            "threshold": thr, "system_fpr": rf_fpr + budget,
            "novelty_combined": combined_rate, "novelty_if_added": added,
        }
        print(f"{budget:>10.2%} {rf_fpr + budget:>11.3%} {combined_rate:>17.1%} {added:>9.1%}")

    selected = sweep[f"{SELECTED_IF_BUDGET:.4f}"]
    anchors = {
        "score_at_confidence_060": selected["threshold"],
        "score_at_confidence_095": float(np.quantile(s_benign[unseen], SELECTED_IF_BUDGET / 10)),
    }
    print(f"\nOperating point: IF budget {SELECTED_IF_BUDGET:.2%}, "
          f"threshold {selected['threshold']:.6f}, "
          f"system FPR {selected['system_fpr']:.3%}, "
          f"novelty {selected['novelty_combined']:.1%}")
    print(f"Confidence calibration anchors: {anchors}")

    model = Pipeline([("scale", transform), ("iforest", forest)])
    joblib.dump(model, WINNER_PATH, compress=3)
    metrics = {
        "seed": SEED,
        "rf_confidence_threshold": RF_CONFIDENCE_THRESHOLD,
        "total_fpr_budget": TOTAL_FPR_BUDGET,
        "rf_benign_fpr": rf_fpr,
        "results": results,
        "selected": {"max_samples": best["max_samples"], "n_estimators": best["n_estimators"]},
        "budget_sweep": sweep,
        "selected_if_budget": SELECTED_IF_BUDGET,
        "selected_threshold": selected["threshold"],
        "selected_system_fpr": selected["system_fpr"],
        "selected_novelty_detection": selected["novelty_combined"],
        "calibration_anchors": anchors,
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    for tmp in (ROOT / "data").glob("_probe_if_*.joblib"):
        tmp.unlink()
    print(f"\nSaved {WINNER_PATH} and {METRICS_PATH}")


if __name__ == "__main__":
    main()
