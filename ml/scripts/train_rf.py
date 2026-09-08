"""在 prepared 数据集上训练随机森林基线模型。
Train a baseline Random Forest classifier on the prepared dataset.

输出:
- ml/data/rf_baseline.joblib          训练好的模型
  trained model
- ml/artifacts/metrics_baseline.json  验证集指标
  validation metrics
"""

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "prepared.npz"
MODEL_PATH = ROOT / "data" / "rf_baseline.joblib"
METRICS_PATH = ROOT / "artifacts" / "metrics_baseline.json"
SEED = 42

# 良性类在 class_names 中的索引
# Benign class index in class_names
BENIGN = 0


def benign_fpr(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """良性误报率：良性样本被误判为攻击的比例。
    Benign false-positive rate: benign rows misclassified as attacks."""
    benign_mask = y_true == BENIGN
    return float((y_pred[benign_mask] != BENIGN).mean())


def system_view(X: np.ndarray, y_true: np.ndarray, y_pred: np.ndarray,
                class_names: list[str], min_packets: int) -> dict:
    """模拟 PreFilter：包数低于阈值的流不进入模型，视为良性。
    Simulate PreFilter: flows below min_packets never reach the model."""
    total_pkts = X[:, 1] + X[:, 2]  # 正向包数 + 反向包数
                                    # total_fwd_packets + total_bwd_packets
    effective = np.where(total_pkts < min_packets, BENIGN, y_pred)
    out = {"min_packets": min_packets, "benign_fpr": benign_fpr(y_true, effective)}
    for idx, name in enumerate(class_names):
        if idx == BENIGN:
            continue
        mask = y_true == idx
        out[f"{name}_recall"] = float((effective[mask] == idx).mean())
    return out


def main() -> None:
    data = np.load(DATA_PATH)
    X_train, y_train = data["X_train"], data["y_train"]
    X_val, y_val = data["X_val"], data["y_val"]
    class_names = data["class_names"].tolist()
    feature_names = data["feature_names"].tolist()

    # 调参前的基线超参数
    # Baseline hyperparameters chosen before tuning
    model = RandomForestClassifier(
        n_estimators=100,
        min_samples_leaf=5,
        n_jobs=-1,
        random_state=SEED,
    )
    start = time.perf_counter()
    model.fit(X_train, y_train)
    fit_seconds = time.perf_counter() - start
    print(f"Fit: {fit_seconds:.1f}s on {len(y_train):,} rows\n")

    y_pred = model.predict(X_val)

    # 验证集上的纯模型视角
    # Pure model view on validation set
    print("=== Validation metrics (pure model view) ===")
    print(classification_report(y_val, y_pred, target_names=class_names, digits=4))
    fpr = benign_fpr(y_val, y_pred)
    print(f"Benign FPR: {fpr:.4%}  "
          f"({int((y_val == BENIGN).sum()):,} benign rows, "
          f"{int(((y_val == BENIGN) & (y_pred != BENIGN)).sum()):,} false alarms)\n")

    print("Confusion matrix (rows=true, cols=pred):")
    cm = confusion_matrix(y_val, y_pred)
    width = max(len(c) for c in class_names) + 2
    print(" " * width + "".join(f"{c:>12}" for c in class_names))
    for name, row in zip(class_names, cm):
        print(f"{name:<{width}}" + "".join(f"{v:>12,}" for v in row))
    print()

    print("Top feature importances:")
    order = np.argsort(model.feature_importances_)[::-1]
    for i in order[:10]:
        print(f"    {feature_names[i]:<22} {model.feature_importances_[i]:.4f}")
    print()

    # 叠加 PreFilter 的系统级视角
    # System view with PreFilter simulation
    print("=== System-level view (pre-filter simulation on val) ===")
    system_views = []
    for min_packets in (3, 2):
        view = system_view(X_val, y_val, y_pred, class_names, min_packets)
        system_views.append(view)
        recalls = ", ".join(
            f"{k.removesuffix('_recall')}: {v:.2%}"
            for k, v in view.items() if k.endswith("_recall")
        )
        print(f"    min_packets={min_packets}: benign FPR {view['benign_fpr']:.4%} | "
              f"recall {recalls}")

    report = classification_report(
        y_val, y_pred, target_names=class_names, digits=4, output_dict=True
    )
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps({
        "model": "RandomForestClassifier(n_estimators=100, min_samples_leaf=5)",
        "seed": SEED,
        "fit_seconds": round(fit_seconds, 1),
        "train_rows": int(len(y_train)),
        "val_rows": int(len(y_val)),
        "classification_report": report,
        "benign_fpr": fpr,
        "confusion_matrix": cm.tolist(),
        "feature_importances": {
            feature_names[i]: float(model.feature_importances_[i]) for i in order
        },
        "system_views": system_views,
    }, indent=2), encoding="utf-8")
    joblib.dump(model, MODEL_PATH, compress=3)
    print(f"\nSaved {METRICS_PATH}")
    print(f"Saved {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
