"""Download the SMS Spam Collection dataset.

Source: Almeida, T.A. & Gómez Hidalgo, J.M. (2011). "SMS Spam Collection".
UCI Machine Learning Repository. https://doi.org/10.24432/C5CC84 (CC BY 4.0)

The script tries the official UCI archive first and falls back to a public
GitHub mirror of the identical tab-separated file. The result is written to
``ml/data/raw/SMSSpamCollection.tsv`` with the format ``<label>\\t<message>``.

Usage (from repository root):
    python -m ml.download_data
    python -m ml.download_data --force   # re-download even if present
"""

from __future__ import annotations

import argparse
import io
import sys
import zipfile
from pathlib import Path

if __package__ in (None, ""):  # allow `python ml/download_data.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests

from ml.config import RAW_DATA_FILE, ensure_dirs

UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
MIRROR_TSV_URL = (
    "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
)
TIMEOUT_SECONDS = 30
EXPECTED_MIN_ROWS = 5000


def _from_uci() -> str:
    response = requests.get(UCI_ZIP_URL, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        return archive.read("SMSSpamCollection").decode("utf-8", errors="replace")


def _from_mirror() -> str:
    response = requests.get(MIRROR_TSV_URL, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.content.decode("utf-8", errors="replace")


def _validate(content: str) -> int:
    lines = [line for line in content.splitlines() if line.strip()]
    valid = [line for line in lines if line.split("\t", 1)[0] in {"ham", "spam"}]
    if len(valid) < EXPECTED_MIN_ROWS:
        raise ValueError(f"Downloaded file looks wrong: only {len(valid)} valid rows.")
    return len(valid)


def download(force: bool = False) -> Path:
    """Download the dataset (if needed) and return the local file path."""
    ensure_dirs()
    if RAW_DATA_FILE.exists() and not force:
        print(f"[download] Dataset already present at {RAW_DATA_FILE}")
        return RAW_DATA_FILE

    errors: list[str] = []
    for name, fetch in (("UCI repository", _from_uci), ("GitHub mirror", _from_mirror)):
        try:
            print(f"[download] Fetching from {name} ...")
            content = fetch()
            rows = _validate(content)
            RAW_DATA_FILE.write_text(content, encoding="utf-8")
            print(f"[download] Saved {rows} rows to {RAW_DATA_FILE}")
            return RAW_DATA_FILE
        except Exception as exc:  # noqa: BLE001 - try the next source
            errors.append(f"{name}: {exc}")
            print(f"[download] {name} failed: {exc}")

    raise RuntimeError("All dataset sources failed:\n  " + "\n  ".join(errors))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="re-download the dataset")
    args = parser.parse_args()
    download(force=args.force)


if __name__ == "__main__":
    main()
