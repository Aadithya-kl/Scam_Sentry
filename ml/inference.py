"""Inference helpers shared by the CLI (`ml/predict.py`) and the FastAPI backend."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
from sklearn.pipeline import Pipeline

from ml.config import MODEL_FILE, SPAM_LABEL
from ml.preprocessing import display_term

VECTORIZER_STEP = "tfidf"
CLASSIFIER_STEP = "clf"


@dataclass(frozen=True)
class TermContribution:
    """A single TF-IDF feature and its contribution to the spam logit."""

    term: str
    weight: float


def load_model(path: Path | str = MODEL_FILE) -> Pipeline:
    """Load the persisted ``TfidfVectorizer -> LogisticRegression`` pipeline."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Model artifact not found at {path}. Train it with `python -m ml.train`."
        )
    model = joblib.load(path)
    if not isinstance(model, Pipeline):
        raise TypeError(f"Expected a scikit-learn Pipeline, got {type(model).__name__}")
    return model


def spam_probability(model: Pipeline, text: str) -> float:
    """Return P(SPAM | text) according to the classifier."""
    classes = list(model.classes_)
    proba = model.predict_proba([text])[0]
    return float(proba[classes.index(SPAM_LABEL)])


def top_contributing_terms(
    model: Pipeline, text: str, k: int = 6, skip_stop_words: bool = True
) -> list[TermContribution]:
    """Explain a prediction via per-term contributions to the spam logit.

    For a linear model, ``logit = b + Σ tfidf(term) · coef(term)``, so each
    term's contribution is simply ``tfidf(term) · coef(term)``. Positive values
    push the prediction toward SPAM, negative values toward SAFE.

    Returns the ``k`` terms present in the message with the largest positive
    contribution (i.e. the words that made the message look most like spam).
    Features made only of stop words ("your", "to the") are skipped for display
    because they carry little meaning for a human reader - the model itself
    still uses them.
    """
    vectorizer = model.named_steps[VECTORIZER_STEP]
    classifier = model.named_steps[CLASSIFIER_STEP]

    row = vectorizer.transform([text])
    if row.nnz == 0:
        return []

    coef = classifier.coef_[0]
    # coef_ is expressed relative to classes_[1]; flip sign if SPAM is classes_[0].
    if list(classifier.classes_).index(SPAM_LABEL) == 0:
        coef = -coef

    indices = row.indices
    contributions = row.data * coef[indices]
    order = np.argsort(contributions)[::-1]
    features = vectorizer.get_feature_names_out()

    result: list[TermContribution] = []
    for i in order:
        if len(result) >= k or contributions[i] <= 0:
            break
        feature = features[indices[i]]
        if skip_stop_words and all(word in ENGLISH_STOP_WORDS for word in feature.split()):
            continue
        result.append(
            TermContribution(term=display_term(feature), weight=round(float(contributions[i]), 4))
        )
    return result
