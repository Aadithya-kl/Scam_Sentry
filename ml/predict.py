"""Command-line prediction using the ML spam classifier only.

This script deliberately exposes the *raw model output* (SAFE vs SPAM
probability + contributing terms). The full SAFE / SPAM / SCAM verdict,
which also applies the heuristic scam-risk layer, is served by the backend.

Usage (from repository root):
    python -m ml.predict "Congratulations! You won a FREE prize, call now"
    echo "See you at 7?" | python -m ml.predict
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python ml/predict.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.config import MODEL_FILE, SAFE_LABEL, SPAM_LABEL
from ml.inference import load_model, spam_probability, top_contributing_terms
from ml.preprocessing import clean_text


def main() -> None:
    parser = argparse.ArgumentParser(description="Classify a message as SAFE or SPAM.")
    parser.add_argument("text", nargs="?", help="message text (reads stdin if omitted)")
    parser.add_argument("--model", default=str(MODEL_FILE), help="path to the joblib pipeline")
    parser.add_argument("--threshold", type=float, default=0.5, help="spam decision threshold")
    args = parser.parse_args()

    text = args.text if args.text is not None else sys.stdin.read()
    if not text.strip():
        parser.error("message text is empty")

    model = load_model(args.model)
    p_spam = spam_probability(model, text)
    label = SPAM_LABEL if p_spam >= args.threshold else SAFE_LABEL

    print(f"Cleaned text     : {clean_text(text)}")
    print(f"Prediction       : {label}")
    print(f"Spam probability : {p_spam:.4f}")
    terms = top_contributing_terms(model, text)
    if terms:
        print("Top spam terms   : " + ", ".join(f"{t.term} (+{t.weight:.3f})" for t in terms))


if __name__ == "__main__":
    main()
