"""Tests for the trained model artifact and inference helpers."""

import json

import pytest
from sklearn.pipeline import Pipeline

from ml.config import METRICS_FILE, SAFE_LABEL, SPAM_LABEL
from ml.inference import load_model, spam_probability, top_contributing_terms


def test_model_loads_as_pipeline(model):
    assert isinstance(model, Pipeline)
    assert set(model.classes_) == {SAFE_LABEL, SPAM_LABEL}
    assert list(model.named_steps) == ["tfidf", "clf"]


def test_missing_model_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_model(tmp_path / "nope.joblib")


def test_probability_is_valid(model):
    p = spam_probability(model, "hello there")
    assert 0.0 <= p <= 1.0


def test_obvious_spam_scores_high(model):
    text = "WINNER!! You have won a FREE £1000 prize. Call 09061701461 now to claim. T&C apply"
    assert spam_probability(model, text) > 0.8
    assert model.predict([text])[0] == SPAM_LABEL


def test_casual_message_scores_low(model):
    text = "Hey, are we still meeting for lunch tomorrow? Let me know"
    assert spam_probability(model, text) < 0.2
    assert model.predict([text])[0] == SAFE_LABEL


def test_top_terms_are_positive_and_non_stopwords(model):
    terms = top_contributing_terms(model, "FREE entry! Text WIN to 80086 to claim your prize", k=5)
    assert 0 < len(terms) <= 5
    assert all(t.weight > 0 for t in terms)
    assert all(t.term not in {"to", "your"} for t in terms)


def test_metrics_file_is_reasonable():
    if not METRICS_FILE.exists():
        pytest.skip("metrics.json missing - run `python -m ml.train`.")
    metrics = json.loads(METRICS_FILE.read_text())
    for key in ("accuracy", "precision", "recall", "f1"):
        assert 0.8 <= metrics[key] <= 1.0
