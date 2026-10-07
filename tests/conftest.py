"""Shared pytest fixtures."""

from __future__ import annotations

import os

# Test-only environment. Must be set before the app (and numpy/OpenBLAS) is imported.
# - No live OpenPhish download during tests (tests seed the cache directly).
# - High rate limit so the suite itself is never throttled.
# - Single-threaded BLAS keeps per-process memory small and deterministic.
os.environ["OPENPHISH_BACKGROUND_REFRESH"] = "false"
os.environ["RATE_LIMIT_PER_MINUTE"] = "100000"
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import pytest
from fastapi.testclient import TestClient

from ml.config import MODEL_FILE

requires_model = pytest.mark.skipif(
    not MODEL_FILE.exists(),
    reason="Model artifact missing - run `python -m ml.train` first.",
)


@pytest.fixture(scope="session")
def model():
    from ml.inference import load_model

    if not MODEL_FILE.exists():
        pytest.skip("Model artifact missing - run `python -m ml.train` first.")
    return load_model()


@pytest.fixture(scope="session")
def client():
    from backend.main import app

    with TestClient(app) as test_client:  # runs the lifespan (model loading + clean shutdown)
        yield test_client
