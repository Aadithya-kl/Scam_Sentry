"""Normalise the raw dataset and create reproducible train/val/test splits.

Steps:
    1. Read the raw tab-separated file (``label<TAB>message``).
    2. Normalise to two columns: ``text`` and ``label`` (ham -> SAFE, spam -> SPAM).
    3. Remove obvious noise: empty messages, stray whitespace, exact duplicates.
       De-duplication matters: the original corpus contains ~400 repeated
       messages, and leaving them in would leak identical rows across splits
       and inflate test scores.
    4. Stratified 70 / 15 / 15 split with a fixed random seed.

Usage (from repository root):
    python -m ml.prepare_data
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python ml/prepare_data.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
from sklearn.model_selection import train_test_split

from ml.config import (
    DATASET_FILE,
    LABEL_MAP,
    RANDOM_SEED,
    RAW_DATA_FILE,
    TEST_FILE,
    TRAIN_FILE,
    VAL_FILE,
    ensure_dirs,
)

TEST_SIZE = 0.15
VAL_SIZE = 0.15


def load_raw(path: Path = RAW_DATA_FILE) -> pd.DataFrame:
    """Load the raw TSV into a DataFrame with ``text`` and ``label`` columns."""
    if not path.exists():
        raise FileNotFoundError(
            f"Raw dataset not found at {path}. Run `python -m ml.download_data` first."
        )
    df = pd.read_csv(
        path,
        sep="\t",
        header=None,
        names=["raw_label", "text"],
        quoting=csv.QUOTE_NONE,  # messages contain unbalanced quotes
        encoding="utf-8",
        dtype=str,
    )
    df["label"] = df["raw_label"].str.strip().str.lower().map(LABEL_MAP)
    return df[["text", "label"]]


def normalise(df: pd.DataFrame) -> pd.DataFrame:
    """Drop invalid rows, tidy whitespace and remove exact duplicates."""
    before = len(df)
    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].str.replace(r"\s+", " ", regex=True).str.strip()
    df = df[df["text"].str.len() > 0]
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    print(f"[prepare] {before} raw rows -> {len(df)} clean, unique rows")
    return df


def split(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Stratified train/validation/test split."""
    train_val, test = train_test_split(
        df, test_size=TEST_SIZE, stratify=df["label"], random_state=RANDOM_SEED
    )
    relative_val = VAL_SIZE / (1 - TEST_SIZE)
    train, val = train_test_split(
        train_val,
        test_size=relative_val,
        stratify=train_val["label"],
        random_state=RANDOM_SEED,
    )
    return train, val, test


def prepare() -> None:
    ensure_dirs()
    df = normalise(load_raw())
    df.to_csv(DATASET_FILE, index=False)

    train, val, test = split(df)
    for name, part, path in (
        ("train", train, TRAIN_FILE),
        ("val", val, VAL_FILE),
        ("test", test, TEST_FILE),
    ):
        part.to_csv(path, index=False)
        spam_share = (part["label"] == "SPAM").mean()
        print(f"[prepare] {name:<5} {len(part):>5} rows  ({spam_share:.1%} spam) -> {path.name}")


if __name__ == "__main__":
    prepare()
