"""Unit tests for ml.preprocessing.clean_text."""

import pytest

from ml.preprocessing import (
    EMAIL_TOKEN,
    EXCLAIM_TOKEN,
    MONEY_TOKEN,
    NUMBER_TOKEN,
    PHONE_TOKEN,
    URL_TOKEN,
    clean_text,
    display_term,
)


def test_lowercases_and_normalises_whitespace():
    assert clean_text("  Hello    WORLD \n\t again ") == "hello world again"


@pytest.mark.parametrize(
    "url",
    ["http://bit.ly/abc123", "https://secure-login.example.com/verify?id=1", "www.prize.com", "claim.xyz/now"],
)
def test_urls_become_placeholder(url):
    out = clean_text(f"Visit {url} today")
    assert out == f"visit {URL_TOKEN} today"


def test_email_replaced_before_url():
    out = clean_text("Contact support@bank.com now")
    assert out == f"contact {EMAIL_TOKEN} now"
    assert URL_TOKEN not in out


@pytest.mark.parametrize("amount", ["£1000", "$4.99", "€50", "₹2,500", "Rs. 500", "100 dollars"])
def test_money_amounts(amount):
    assert MONEY_TOKEN in clean_text(f"You won {amount}").split()


def test_phone_numbers_and_numbers():
    out = clean_text("Call 09061701461 or text 80086")
    assert out == f"call {PHONE_TOKEN} or text {NUMBER_TOKEN}"


def test_exclamation_marks_preserved_as_token():
    assert clean_text("WIN!!!") == f"win {EXCLAIM_TOKEN}"


def test_repeated_characters_squashed():
    assert clean_text("sooooo goooood") == "soo good"


def test_punctuation_removed():
    assert clean_text("hello, world... (really?)") == "hello world really"


def test_html_entities_decoded():
    assert clean_text("I'll be there &lt;#&gt; mins") == "i ll be there mins"


@pytest.mark.parametrize("word", ["free", "win", "otp", "bank", "click", "verify", "account", "money"])
def test_spam_signal_words_are_preserved(word):
    assert word in clean_text(f"Please {word.upper()} now").split()


@pytest.mark.parametrize("value", [None, 123, ""])
def test_non_string_or_empty_input(value):
    assert clean_text(value) == ""


def test_display_term_maps_placeholders():
    assert display_term(f"call {PHONE_TOKEN}") == "call [PHONE NUMBER]"
    assert display_term("free") == "free"
