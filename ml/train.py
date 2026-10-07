"""Train the TF-IDF + Logistic Regression spam classifier.

Workflow:
    1. Load the stratified train / validation splits produced by ``prepare_data``.
    2. Select the regularisation strength ``C`` on the *validation* set
       (optimising spam F1 - the test set is never touched here).
    3. Refit the best configuration on train + validation.
    4. Persist the whole pipeline (preprocessing + vectoriser + classifier)
       as a single joblib artifact, together with ``model_info.json``.
    5. Run the held-out test evaluation and feature analysis.

Usage (from repository root):
    python -m ml.train
"""

from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):  # allow `python ml/train.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

from ml.config import (
    MODEL_FILE,
    MODEL_INFO_FILE,
    RANDOM_SEED,
    SPAM_LABEL,
    TRAIN_FILE,
    VAL_FILE,
    ensure_dirs,
)
from ml.inference import CLASSIFIER_STEP, VECTORIZER_STEP
from ml.preprocessing import clean_text

MODEL_VERSION = "1.0.0"
C_GRID = (0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0)


def build_pipeline(C: float = 10.0) -> Pipeline:
    """Create the (unfitted) ``TfidfVectorizer -> LogisticRegression`` pipeline."""
    vectorizer = TfidfVectorizer(
        preprocessor=clean_text,  # same cleaning at train and inference time
        ngram_range=(1, 2),  # unigrams + bigrams ("click here", "call now")
        min_df=2,  # ignore hapax terms (typos, one-off names)
        max_df=0.95,
        sublinear_tf=True,  # dampen repeated words
        max_features=30_000,
    )
    classifier = LogisticRegression(
        C=C,
        class_weight="balanced",  # dataset is ~13% spam
        solver="liblinear",
        max_iter=2000,
        random_state=RANDOM_SEED,
    )
    return Pipeline([(VECTORIZER_STEP, vectorizer), (CLASSIFIER_STEP, classifier)])


def _load_split(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"{path} not found. Run `python -m ml.prepare_data` first.")
    return pd.read_csv(path, dtype=str).dropna()


def select_c(train: pd.DataFrame, val: pd.DataFrame) -> tuple[float, list[dict]]:
    """Grid-search C on the validation split; return best C and the full log."""
    results = []
    for c in C_GRID:
        model = build_pipeline(C=c).fit(train["text"], train["label"])
        pred = model.predict(val["text"])
        row = {
            "C": c,
            "precision": precision_score(val["label"], pred, pos_label=SPAM_LABEL),
            "recall": recall_score(val["label"], pred, pos_label=SPAM_LABEL),
            "f1": f1_score(val["label"], pred, pos_label=SPAM_LABEL),
        }
        results.append({k: round(v, 4) for k, v in row.items()})
        print(
            f"[train] C={c:<5} val precision={row['precision']:.4f} "
            f"recall={row['recall']:.4f} f1={row['f1']:.4f}"
        )
    best = max(results, key=lambda r: (r["f1"], -r["C"]))  # tie -> simpler model
    return best["C"], results


def train() -> Pipeline:
    ensure_dirs()
    train_df = _load_split(TRAIN_FILE)
    val_df = _load_split(VAL_FILE)
    print(f"[train] train={len(train_df)} rows, val={len(val_df)} rows")

    best_c, search_log = select_c(train_df, val_df)
    print(f"[train] Selected C={best_c} (best validation F1)")

    full = pd.concat([train_df, val_df], ignore_index=True)
    model = build_pipeline(C=best_c).fit(full["text"], full["label"])

    joblib.dump(model, MODEL_FILE, compress=3)
    vocab_size = len(model.named_steps[VECTORIZER_STEP].vocabulary_)
    info = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "TfidfVectorizer(1-2 grams) + LogisticRegression(class_weight=balanced)",
        "dataset": "SMS Spam Collection (UCI, CC BY 4.0)",
        "classes": list(model.classes_),
        "selected_C": best_c,
        "c_search": search_log,
        "training_rows": len(full),
        "vocabulary_size": vocab_size,
        "random_seed": RANDOM_SEED,
        "python_version": platform.python_version(),
        "sklearn_version": sklearn.__version__,
    }
    MODEL_INFO_FILE.write_text(json.dumps(info, indent=2), encoding="utf-8")
    size_kb = MODEL_FILE.stat().st_size / 1024
    print(f"[train] Saved pipeline -> {MODEL_FILE} ({size_kb:.0f} KB, vocab={vocab_size})")
    return model


def main() -> None:
    train()
    # Held-out evaluation and feature analysis run automatically after training.
    from ml import evaluate, feature_analysis

    evaluate.evaluate()
    feature_analysis.analyse()


if __name__ == "__main__":
    main()
