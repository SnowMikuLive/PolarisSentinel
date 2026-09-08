"""在已训练随机森林基础上联合调优孤立森林（并行架构）。
Tune Isolation Forest jointly with the trained Random Forest (parallel architecture).

孤立森林仅对 RF 判定为良性的流打分；两者误报预算可叠加。
IF only scores flows that RF already called benign; budgets are additive.

输出:
- ml/data/if_winner.joblib              选定的流水线模型
  selected pipeline
- ml/artifacts/metrics_if_system.json   系统级指标
  system-level metrics
"""

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
# 仅在训练集上训练，验证集保持干净
# trained on train only; val is clean
METRICS_PATH = ROOT / "artifacts" / "metrics_if_system.json"
WINNER_PATH = ROOT / "data" / "if_winner.joblib"

SEED = 42
BENIGN = 0
FIT_ROWS = 300_000

RF_CONFIDENCE_THRESHOLD = 0.60  # 需与 PolicySettings 一致
                                   # Must match PolicySettings
TOTAL_FPR_BUDGET = 0.010        # 全系统良性误报 ≤ 1%
                                 # Whole system stays within 1% benign FPR

# 预算曲线拐点：超过 0.1% 后，告警噪声增速超过检测收益
# Knee of the budget curve: beyond 0.1% IF budget, alert noise rises faster than detection gain
SELECTED_IF_BUDGET = 0.001

# 先跑轻量配置，内存不足时仍保留部分结果
# Cheapest configs first so partial results survive OOM
GRID = [
    (32768, 100), (32768, 200), (65536, 100), (65536, 200), (131072, 100),
]


def rf_alerts(rf, X: np.ndarray, class_names: list[str]) -> np.ndarray:
    """RF 产生可执行（非良性）告警的位置为 True。
    True where RF raises an actionable (non-benign) alert."""
    proba = rf.predict_proba(X)
    pred = proba.argmax(axis=1)
    conf = proba.max(axis=1)
    return (pred != BENIGN) & (conf >= RF_CONFIDENCE_THRESHOLD)


def main() -> None:
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
    known_val = {cls: X_val[y_val == i] for i, cls in enumerate(class_names) if i != BENIGN}

    rng = np.random.default_rng(SEED)
    fit_idx = rng.choice(len(benign_train), size=min(FIT_ROWS, len(benign_train)), replace=False)
    X_fit = benign_train[fit_idx]

    print("Fitting PowerTransformer (winner of the 9/7 transform comparison)...")
    transform = PowerTransformer(method="yeo-johnson").fit(X_fit)
    T_fit = transform.transform(X_fit)
    T_benign = transform.transform(benign_val)
    T_novelty = transform.transform(X_novelty)
    T_known = {cls: transform.transform(rows) for cls, rows in known_val.items()}

    print("Scoring the Random Forest once (defines what Isolation Forest ever sees)...")
    benign_rf_alert = rf_alerts(rf, benign_val, class_names)
    novelty_rf_alert = rf_alerts(rf, X_novelty, class_names)
    known_rf_alert = {cls: rf_alerts(rf, rows, class_names) for cls, rows in known_val.items()}

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

        # IF 阈值在 RF 未告警的良性流上选取；误报成本按全部良性流计算，使两阶段预算可加
        # IF threshold is chosen on RF-silent benign flows; cost is charged on all benign flows
        unseen = ~benign_rf_alert
        quantile_level = if_budget * len(benign_val) / unseen.sum()
        threshold = float(np.quantile(s_benign[unseen], quantile_level))

        if_extra_fpr = float((unseen & (s_benign < threshold)).mean())
        system_fpr = rf_fpr + if_extra_fpr

        if_catch = ~novelty_rf_alert & (s_novelty < threshold)
        combined = novelty_rf_alert | if_catch

        per_group = {
            g: {
                "rf": float(novelty_rf_alert[novelty_groups == g].mean()),
                "if": float(if_catch[novelty_groups == g].mean()),
                "combined": float(combined[novelty_groups == g].mean()),
            }
            for g in group_names
        }

        # IF 能否补上 RF 漏掉的已知攻击？
        # Can IF rescue known attacks that RF missed?
        known_rescue = {}
        for cls, rows in T_known.items():
            missed = ~known_rf_alert[cls]
            scores = forest.decision_function(rows)
            known_rescue[cls] = {
                "rf": float(known_rf_alert[cls].mean()),
                "combined": float((known_rf_alert[cls] | (missed & (scores < threshold))).mean()),
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
        print("    " + ", ".join(
            f"{g} {per_group[g]['combined']:.0%}" for g in group_names))
        METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
        METRICS_PATH.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")

    # 架构对比：并行（本项目） vs 门控（提案描述）
    # Architecture comparison: parallel (ours) vs gate (proposal)
    best = max(results, key=lambda r: r["novelty"]["combined"] - 0.02 * r["joblib_mb"])
    print(f"\nSelected: max_samples {best['max_samples']} x {best['n_estimators']} trees "
          f"({best['joblib_mb']} MB)")

    forest = IsolationForest(
        n_estimators=best["n_estimators"], max_samples=best["max_samples"],
        random_state=SEED, n_jobs=-1,
    ).fit(T_fit)
    s_benign = forest.decision_function(T_benign)

    # 门控架构：IF 在前过滤，需独自承担全部误报预算
    # Gate architecture: IF filters first, so it must fund the entire FPR budget alone
    gate_threshold = float(np.quantile(s_benign, TOTAL_FPR_BUDGET))
    print(f"\nArchitecture comparison at a {TOTAL_FPR_BUDGET:.0%} benign FPR budget")
    print(f"{'class':<12} {'parallel (RF sees all)':>24} {'gate (IF filters first)':>26}")
    for cls, rows in T_known.items():
        gate_pass = forest.decision_function(rows) < gate_threshold
        gate_detect = float((gate_pass & known_rf_alert[cls]).mean())
        print(f"{cls:<12} {known_rf_alert[cls].mean():>23.1%} {gate_detect:>25.1%}")

    # 预算扫描：IF 预算花到哪里性价比最高？
    # Budget sweep: how much IF budget is actually worth spending?
    # 未知异常仅触发 Monitor 告警（仪表盘噪声，不自动封禁）
    # Unknown anomalies only raise Monitor alerts (dashboard noise, not auto-block)
    unseen = ~benign_rf_alert
    s_novelty = forest.decision_function(T_novelty)
    print(f"\n{'IF budget':>10} {'system FPR':>11} {'novelty detected':>17} {'IF adds':>9}")
    sweep = {}
    for budget in (0.0005, SELECTED_IF_BUDGET, 0.002, 0.005, if_budget):
        level = budget * len(benign_val) / unseen.sum()
        thr = float(np.quantile(s_benign[unseen], level))
        added = float((~novelty_rf_alert & (s_novelty < thr)).mean())
        combined_rate = float((novelty_rf_alert | (~novelty_rf_alert & (s_novelty < thr))).mean())
        sweep[f"{budget:.4f}"] = {
            "threshold": thr, "system_fpr": rf_fpr + budget,
            "novelty_combined": combined_rate, "novelty_if_added": added,
        }
        print(f"{budget:>10.2%} {rf_fpr + budget:>11.3%} {combined_rate:>17.1%} {added:>9.1%}")

    # 将异常分数映射到 [0,1]，使 DetectionResult.Confidence 在不同模型间可比
    # Map anomaly score to [0,1] so DetectionResult.Confidence is comparable across models
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

    joblib.dump(Pipeline([("scale", transform), ("iforest", forest)]), WINNER_PATH, compress=3)
    METRICS_PATH.write_text(json.dumps({
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
    }, indent=2), encoding="utf-8")

    for tmp in (ROOT / "data").glob("_probe_if_*.joblib"):
        tmp.unlink()
    print(f"\nSaved {WINNER_PATH} and {METRICS_PATH}")


if __name__ == "__main__":
    main()
