"""Text preprocessing shared by training and inference.

The same :func:`clean_text` function is embedded inside the saved scikit-learn
pipeline (as the ``TfidfVectorizer`` preprocessor), which guarantees that the
backend applies *exactly* the same transformation that was used in training.

Design principle: normalise noise, but keep signal. Spam detection benefits
from knowing *that* a message contains a URL, a phone number or a currency
amount, so those entities are replaced by placeholder tokens rather than
being deleted. Words such as "free", "win", "otp", "bank", "verify" are kept
as-is (lower-cased) and no stop-word removal is applied.
"""

from __future__ import annotations

import html
import re

# Placeholder tokens. They are plain alphabetic words so that the default
# TF-IDF tokenizer keeps them as single features.
URL_TOKEN = "urltoken"
EMAIL_TOKEN = "emailtoken"
MONEY_TOKEN = "moneytoken"
PHONE_TOKEN = "phonetoken"
NUMBER_TOKEN = "numtoken"
EXCLAIM_TOKEN = "exclaimtoken"

PLACEHOLDER_TOKENS = {
    URL_TOKEN: "[URL]",
    EMAIL_TOKEN: "[EMAIL]",
    MONEY_TOKEN: "[MONEY AMOUNT]",
    PHONE_TOKEN: "[PHONE NUMBER]",
    NUMBER_TOKEN: "[NUMBER]",
    EXCLAIM_TOKEN: "[!]",
}

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_URL_RE = re.compile(
    r"""(
        https?://\S+                      # explicit scheme
      | www\.\S+                          # www. prefix
      | \b[a-z0-9-]+(?:\.[a-z0-9-]+)*     # bare domain ...
        \.(?:com|net|org|info|biz|co|io|ly|me|uk|in|xyz|top|click|link|online|site|live|ru|cn)
        \b(?:/\S*)?                       # ... with optional path
    )""",
    re.IGNORECASE | re.VERBOSE,
)
_MONEY_RE = re.compile(
    r"(?:[£$€₹]\s?\d[\d,]*(?:\.\d+)?)"
    r"|(?:\b(?:rs\.?|inr|usd|gbp|eur)\s?\d[\d,]*(?:\.\d+)?)"
    r"|(?:\b\d[\d,]*(?:\.\d+)?\s?(?:pounds?|dollars?|euros?|rupees?|usd|gbp|inr)\b)",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(r"\+?\d[\d\s-]{8,}\d")
_NUMBER_RE = re.compile(r"\b\d+\b")
_EXCLAIM_RE = re.compile(r"!+")
_REPEAT_RE = re.compile(r"([a-z])\1{2,}")  # 3+ repeated letters -> 2
_NON_ALNUM_RE = re.compile(r"[^a-z0-9\s]")
_WHITESPACE_RE = re.compile(r"\s+")


def clean_text(text: str) -> str:
    """Normalise a raw message for TF-IDF vectorisation.

    Steps (order matters):
        1. decode HTML entities (``&lt;`` -> ``<``) and lower-case
        2. e-mail addresses  -> ``emailtoken``   (before URLs: emails contain domains)
        3. URLs / domains    -> ``urltoken``
        4. currency amounts  -> ``moneytoken``
        5. phone numbers     -> ``phonetoken``
        6. other numbers     -> ``numtoken``
        7. ``!``-runs        -> ``exclaimtoken``
        8. squash 3+ repeated letters to two (``soooo`` -> ``soo``, ``freeee`` -> ``free``)
        9. strip remaining punctuation
        10. normalise whitespace

    Args:
        text: Raw message text. ``None``/non-strings are treated as empty.

    Returns:
        The cleaned, space-separated text.
    """
    if not isinstance(text, str):
        return ""

    text = html.unescape(text).lower()
    text = _EMAIL_RE.sub(f" {EMAIL_TOKEN} ", text)
    text = _URL_RE.sub(f" {URL_TOKEN} ", text)
    text = _MONEY_RE.sub(f" {MONEY_TOKEN} ", text)
    text = _PHONE_RE.sub(f" {PHONE_TOKEN} ", text)
    text = _NUMBER_RE.sub(f" {NUMBER_TOKEN} ", text)
    text = _EXCLAIM_RE.sub(f" {EXCLAIM_TOKEN} ", text)
    text = _REPEAT_RE.sub(r"\1\1", text)
    text = _NON_ALNUM_RE.sub(" ", text)
    text = _WHITESPACE_RE.sub(" ", text)
    return text.strip()


def display_term(term: str) -> str:
    """Convert internal feature names (e.g. ``urltoken``) to readable labels."""
    return " ".join(PLACEHOLDER_TOKENS.get(part, part) for part in term.split())
