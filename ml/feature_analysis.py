"""Inspect what the classifier has learned.

Because the model is linear, each TF-IDF feature has a single coefficient:
positive -> evidence for SPAM, negative -> evidence for SAFE. This script
exports the strongest features in both directions.

Outputs:
    ml/artifacts/top_features.json
    ml/plots/top_features.png

Usage (from repository root):
    python -m ml.feature_analysis
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python ml/feature_analysis.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from ml.config import MODEL_FILE, PLOTS_DIR, SPAM_LABEL, TOP_FEATURES_FILE, ensure_dirs
from ml.inference import CLASSIFIER_STEP, VECTORIZER_STEP, load_model
from ml.preprocessing import display_term

TOP_K = 20


def analyse(model_path: Path = MODEL_FILE, k: int = TOP_K) -> dict:
    ensure_dirs()
    model = load_model(model_path)
    features = model.named_steps[VECTORIZER_STEP].get_feature_names_out()
    classifier = model.named_steps[CLASSIFIER_STEP]
    coef = classifier.coef_[0]
    if list(classifier.classes_).index(SPAM_LABEL) == 0:
        coef = -coef

    order = np.argsort(coef)
    spam_idx = order[::-1][:k]
    safe_idx = order[:k]

    result = {
        "spam_indicators": [
            {"term": display_term(features[i]), "coefficient": round(float(coef[i]), 4)} for i in spam_idx
        ],
        "safe_indicators": [
            {"term": display_term(features[i]), "coefficient": round(float(coef[i]), 4)} for i in safe_idx
        ],
    }
    TOP_FEATURES_FILE.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[features] Top spam terms: {', '.join(t['term'] for t in result['spam_indicators'][:10])}")
    print(f"[features] Top safe terms: {', '.join(t['term'] for t in result['safe_indicators'][:10])}")
    print(f"[features] Saved -> {TOP_FEATURES_FILE}")

    fig, axes = plt.subplots(1, 2, figsize=(11, 6))
    for ax, key, colour, title in (
        (axes[0], "spam_indicators", "#f59e0b", "Strongest SPAM indicators"),
        (axes[1], "safe_indicators", "#34d399", "Strongest SAFE indicators"),
    ):
        items = result[key][::-1]
        ax.barh([t["term"] for t in items], [abs(t["coefficient"]) for t in items], color=colour)
        ax.set_title(title)
        ax.set_xlabel("|coefficient|")
    fig.suptitle("Logistic Regression coefficients (TF-IDF features)")
    fig.tight_layout()
    path = PLOTS_DIR / "top_features.png"
    fig.savefig(path, dpi=140)
    plt.close(fig)
    print(f"[features] Plot saved -> {path}")
    return result


if __name__ == "__main__":
    analyse()
