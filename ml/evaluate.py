"""Evaluate the trained pipeline on the held-out test split.

Outputs:
    ml/artifacts/metrics.json         accuracy, precision, recall, F1, ROC-AUC, confusion matrix
    ml/plots/confusion_matrix.png
    ml/plots/roc_curve.png
    ml/plots/precision_recall_curve.png
    ml/plots/class_distribution.png

Usage (from repository root):
    python -m ml.evaluate
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python ml/evaluate.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import matplotlib

matplotlib.use("Agg")  # headless backend - no display required
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from ml.config import (
    DATASET_FILE,
    METRICS_FILE,
    MODEL_FILE,
    PLOTS_DIR,
    SAFE_LABEL,
    SPAM_LABEL,
    TEST_FILE,
    ensure_dirs,
)
from ml.inference import load_model

ACCENT = "#22d3ee"
sns.set_theme(style="whitegrid")


def _save(fig: plt.Figure, name: str) -> None:
    path = PLOTS_DIR / name
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    print(f"[evaluate] Plot saved -> {path}")


def plot_confusion(cm, labels: list[str]) -> None:
    fig, ax = plt.subplots(figsize=(4.8, 4.2))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False,
                xticklabels=labels, yticklabels=labels, ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion matrix (test set)")
    _save(fig, "confusion_matrix.png")


def plot_roc(y_true, scores, auc: float) -> None:
    fpr, tpr, _ = roc_curve(y_true, scores)
    fig, ax = plt.subplots(figsize=(5, 4.2))
    ax.plot(fpr, tpr, color=ACCENT, lw=2, label=f"ROC-AUC = {auc:.4f}")
    ax.plot([0, 1], [0, 1], "--", color="grey", lw=1)
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC curve (test set)")
    ax.legend(loc="lower right")
    _save(fig, "roc_curve.png")


def plot_pr(y_true, scores, ap: float) -> None:
    precision, recall, _ = precision_recall_curve(y_true, scores)
    fig, ax = plt.subplots(figsize=(5, 4.2))
    ax.plot(recall, precision, color=ACCENT, lw=2, label=f"Average precision = {ap:.4f}")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-recall curve (test set)")
    ax.legend(loc="lower left")
    _save(fig, "precision_recall_curve.png")


def plot_distribution() -> None:
    if not DATASET_FILE.exists():
        return
    df = pd.read_csv(DATASET_FILE)
    fig, ax = plt.subplots(figsize=(4.8, 3.6))
    sns.countplot(data=df, x="label", order=[SAFE_LABEL, SPAM_LABEL],
                  hue="label", palette=["#34d399", "#f59e0b"], legend=False, ax=ax)
    ax.set_title("Class distribution (deduplicated dataset)")
    ax.set_xlabel("")
    for container in ax.containers:
        ax.bar_label(container)
    _save(fig, "class_distribution.png")


def evaluate(model_path: Path = MODEL_FILE) -> dict:
    ensure_dirs()
    if not TEST_FILE.exists():
        raise FileNotFoundError(f"{TEST_FILE} not found. Run `python -m ml.prepare_data` first.")

    model = load_model(model_path)
    test = pd.read_csv(TEST_FILE, dtype=str).dropna()
    y_true = test["label"]
    y_pred = model.predict(test["text"])
    spam_idx = list(model.classes_).index(SPAM_LABEL)
    scores = model.predict_proba(test["text"])[:, spam_idx]
    y_binary = (y_true == SPAM_LABEL).astype(int)

    labels = [SAFE_LABEL, SPAM_LABEL]
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    auc = roc_auc_score(y_binary, scores)
    ap = average_precision_score(y_binary, scores)

    metrics = {
        "split": "test",
        "n_samples": int(len(test)),
        "positive_class": SPAM_LABEL,
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, pos_label=SPAM_LABEL), 4),
        "recall": round(recall_score(y_true, y_pred, pos_label=SPAM_LABEL), 4),
        "f1": round(f1_score(y_true, y_pred, pos_label=SPAM_LABEL), 4),
        "roc_auc": round(auc, 4),
        "average_precision": round(ap, 4),
        "confusion_matrix": {
            "labels": labels,
            "matrix": cm.tolist(),
            "true_negatives": int(cm[0, 0]),
            "false_positives": int(cm[0, 1]),
            "false_negatives": int(cm[1, 0]),
            "true_positives": int(cm[1, 1]),
        },
        "classification_report": classification_report(
            y_true, y_pred, labels=labels, output_dict=True, zero_division=0
        ),
    }
    METRICS_FILE.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(classification_report(y_true, y_pred, labels=labels, digits=4, zero_division=0))
    print(
        f"[evaluate] accuracy={metrics['accuracy']} precision={metrics['precision']} "
        f"recall={metrics['recall']} f1={metrics['f1']} roc_auc={metrics['roc_auc']}"
    )
    print(f"[evaluate] Metrics saved -> {METRICS_FILE}")

    plot_confusion(cm, labels)
    plot_roc(y_binary, scores, auc)
    plot_pr(y_binary, scores, ap)
    plot_distribution()
    return metrics


if __name__ == "__main__":
    evaluate()
