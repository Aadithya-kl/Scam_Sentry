"""Loads the trained pipeline once and exposes ML inference to the API."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from sklearn.pipeline import Pipeline

from ml.config import MODEL_INFO_FILE
from ml.inference import TermContribution, load_model, spam_probability, top_contributing_terms

logger = logging.getLogger(__name__)


class ModelService:
    """Thin wrapper around the persisted scikit-learn pipeline."""

    def __init__(self, model_path: Path) -> None:
        self.model_path = Path(model_path)
        self._model: Pipeline | None = None
        self.version: str | None = None
        self.load_error: str | None = None

    def load(self) -> None:
        try:
            self._model = load_model(self.model_path)
            self.version = self._read_version()
            self.load_error = None
            logger.info("Model loaded from %s (version %s)", self.model_path, self.version)
        except Exception as exc:  # noqa: BLE001 - surface as degraded health
            self._model = None
            self.load_error = str(exc)
            logger.error("Could not load model: %s", exc)

    def _read_version(self) -> str:
        info_path = self.model_path.with_name(MODEL_INFO_FILE.name)
        try:
            return json.loads(info_path.read_text(encoding="utf-8")).get("model_version", "unknown")
        except (OSError, ValueError):
            return "unknown"

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    def _require(self) -> Pipeline:
        if self._model is None:
            raise RuntimeError(self.load_error or "Model is not loaded.")
        return self._model

    def spam_probability(self, text: str) -> float:
        return spam_probability(self._require(), text)

    def top_terms(self, text: str, k: int = 6) -> list[TermContribution]:
        return top_contributing_terms(self._require(), text, k=k)
