"""Central filesystem locations and constants for the ML pipeline."""

from __future__ import annotations

from pathlib import Path

ML_DIR = Path(__file__).resolve().parent

DATA_DIR = ML_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
ARTIFACTS_DIR = ML_DIR / "artifacts"
PLOTS_DIR = ML_DIR / "plots"

RAW_DATA_FILE = RAW_DIR / "SMSSpamCollection.tsv"
DATASET_FILE = PROCESSED_DIR / "messages.csv"
TRAIN_FILE = PROCESSED_DIR / "train.csv"
VAL_FILE = PROCESSED_DIR / "val.csv"
TEST_FILE = PROCESSED_DIR / "test.csv"

MODEL_FILE = ARTIFACTS_DIR / "scamsentry_model.joblib"
MODEL_INFO_FILE = ARTIFACTS_DIR / "model_info.json"
METRICS_FILE = ARTIFACTS_DIR / "metrics.json"
TOP_FEATURES_FILE = ARTIFACTS_DIR / "top_features.json"

# Reproducibility
RANDOM_SEED = 42

# Label vocabulary used by the ML model. SCAM is *not* a model label;
# it is produced by the backend's heuristic risk layer.
SAFE_LABEL = "SAFE"
SPAM_LABEL = "SPAM"
LABEL_MAP = {"ham": SAFE_LABEL, "spam": SPAM_LABEL}


def ensure_dirs() -> None:
    """Create all output directories used by the pipeline."""
    for directory in (RAW_DIR, PROCESSED_DIR, ARTIFACTS_DIR, PLOTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
