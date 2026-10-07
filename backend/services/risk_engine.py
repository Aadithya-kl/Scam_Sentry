"""Heuristic scam-risk engine.

Scoring is fully explainable.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from backend.utils.url_utils import extract_urls, inspect_url


@dataclass(frozen=True)
class Category:
    key: str
    flag: str
    reason: str
    points: int
    patterns: tuple[str, ...]

    @property
    def regex(self) -> re.Pattern[str]:
        return _compile(self.patterns)


def _compile(patterns: tuple[str, ...]) -> re.Pattern[str]:
    return re.compile(r"(?<!\w)(?:" + "|".join(patterns) + r")(?!\w)", re.IGNORECASE)


CATEGORIES: tuple[Category, ...] = (
    Category(
        key="reward_lure",
        flag="Reward / prize lure",
        reason="The message uses a reward/bonus lure",
        points=20,
        patterns=(
            r"congratulations", r"you(?:'ve| have)? won", r"winner", r"prizes?", r"lottery",
            r"jackpot", r"gift ?cards?", r"rewards?", r"cash ?back", r"vouchers?", r"bonus",
            r"special customer reward", r"lucky draw",
            r"free (?:gift|iphone|phone|laptop|vacation|trip|money)",
        ),
    ),
    Category(
        key="credential_request",
        flag="Credential request",
        reason="It asks for account details or credentials",
        points=25,
        patterns=(
            r"passwords?", r"passcode", r"log ?in(?: details| credentials)?", r"sign ?in",
            r"username", r"account (?:number|details|credentials)",
            r"(?:bank|card|personal) (?:details|information|info)", r"kyc",
            r"date of birth", r"mother'?s maiden name",
        ),
    ),
    Category(
        key="verification_request",
        flag="Account verification request",
        reason="It requests account verification",
        points=20,
        patterns=(
            r"(?:verify|confirm|validate) (?:your )?(?:account|identity|details|password)",
            r"verification(?: page| link)?",
        ),
    ),
    Category(
        key="otp_request",
        flag="OTP / PIN / PASSWORD request",
        reason="It asks for an OTP, PIN, or CVV",
        points=30,
        patterns=(
            r"otp", r"one[- ]time (?:password|passcode|code|pin)",
            r"verification code", r"security code", r"pin(?: number| code)?", r"cvv", r"cvc",
            r"ssn", r"social security(?: number)?",
        ),
    ),
    Category(
        key="urgency",
        flag="Urgent language",
        reason="It uses urgent language",
        points=15,
        patterns=(
            r"urgent(?:ly)?", r"immediately", r"act now", r"right away", r"asap",
            r"today only", r"last chance", r"final (?:notice|warning|reminder)",
        ),
    ),
    Category(
        key="financial_language",
        flag="Financial language",
        reason="It uses financial language",
        points=20,
        patterns=(
            r"bank(?:ing)?", r"refunds?", r"transfer(?:red)?", r"wire",
            r"credit card", r"debit card", r"wallet", r"money", r"cash", r"loans?",
            r"invoice", r"tax(?:es)?",
            r"bitcoin", r"crypto(?:currency)?", r"upi", r"paypal", r"deposit", r"billing",
            r"[£$€₹]\s?\d[\d,]*(?:\.\d+)?", r"(?:rs\.?|inr|usd)\s?\d[\d,]*(?:\.\d+)?",
        ),
    ),
    Category(
        key="payment_request",
        flag="Payment request",
        reason="It asks for a payment or fee",
        points=25,
        patterns=(
            r"payments?", r"(?:processing |delivery |customs |small )?fees?",
            r"pay (?:a |the )?(?:small )?(?:fee|charge|amount|fine)",
            r"send (?:the |us )?(?:money|payment|cash|funds|gift cards?)",
        ),
    ),
    Category(
        key="suspicious_action",
        flag="Suspicious action request",
        reason="It asks the recipient to use a link or click",
        points=15,
        patterns=(
            r"click (?:on )?(?:this|the|here|below)(?: link)?", r"click link",
            r"tap (?:here|on the link|the link|this link)", r"use the (?:verification )?link",
            r"claim (?:your |the |a )?(?:reward|prize|gift|refund|money|cash|voucher|bonus|winnings)",
            r"download(?: the| this)?(?: app| attachment| file)?", r"install",
            r"(?:reply|respond) with (?:your )?\w+",
            r"update (?:your )?(?:details|information|kyc|payment|account|billing)",
        ),
    ),
    Category(
        key="account_suspension",
        flag="Account suspension / blocking threat",
        reason="It threatens account suspension or blocking",
        points=20,
        patterns=(
            r"(?:account|card|number|service|sim|profile|wallet)(?: \w+){0,3} "
            r"(?:suspended|blocked|locked|deactivated|disabled|restricted|frozen|on hold)",
            r"will be (?:suspended|blocked|terminated|closed|deactivated|disconnected|cancell?ed)",
            r"unauthori[sz]ed (?:access|activity|transaction|login|charge)",
            r"(?:unusual|suspicious) (?:activity|sign-?in|login|transaction)",
            r"failure to (?:comply|respond|verify|pay|update)", r"legal action", r"arrest warrant",
        ),
    ),
    Category(
        key="expiration_pressure",
        flag="Urgency / expiration pressure",
        reason="It creates time pressure by saying the offer will expire or is limited time",
        points=10,
        patterns=(
            r"limited[- ]time", r"expires?", r"within \d+ ?(?:hours?|hrs?|minutes?|mins?|days?)",
        ),
    ),
    Category(
        key="account_action",
        flag="Account action request",
        reason="The message asks the recipient to confirm account information",
        points=10,
        patterns=(
            r"(?:confirm|update|verify|review) (?:your )?(?:account|contact|profile|identity|details)",
            r"(?:account|contact|profile) (?:details|information|info) (?:are|is) up to date",
            r"confirm that your details are up to date",
        ),
    ),
    Category(
        key="portal_action",
        flag="Portal / link action",
        reason="It directs the recipient to use an online customer portal",
        points=8,
        patterns=(
            r"(?:customer|secure|online) (?:portal|account)",
            r"(?:verification|confirmation) page",
        ),
    ),
    Category(
        key="deadline_pressure",
        flag="Deadline pressure",
        reason="It introduces a review-window deadline",
        points=10,
        patterns=(
            r"before the (?:review window closes|deadline|cutoff)",
            r"within \d+ hours", r"by the end of the day", r"action required today",
        ),
    ),
    Category(
        key="consequence_threat",
        flag="Consequence / access threat",
        reason="It suggests that failure to act could affect service access",
        points=10,
        patterns=(
            r"access may be (?:delayed|limited)", r"service(?:s)? may be (?:restricted|temporarily unavailable)",
            r"account may be suspended", r"transaction may be blocked",
            r"temporary delay in accessing(?: certain services)?",
        ),
    ),
)


@dataclass
class RiskSignal:
    category: str
    label: str
    points: int
    matches: list[str] = field(default_factory=list)


@dataclass
class RiskAssessment:
    rule_based_score: int
    flags: list[str]
    reasons: list[str]
    breakdown: list[RiskSignal]
    combination_bonus: int = 0


def _normalise(text: str) -> str:
    text = text.replace("\u2019", "'").replace("\u2018", "'")
    return re.sub(r"\s+", " ", text).strip().lower()


def _find(regex: re.Pattern[str], text: str) -> list[str]:
    found: list[str] = []
    for m in regex.finditer(text):
        value = m.group(0).strip()
        if value not in found:
            found.append(value)
    return found


def analyze(text: str) -> RiskAssessment:
    """Score a message based purely on rules, returning the sub-components."""
    raw = text or ""
    urls = extract_urls(raw)

    keyword_text = raw
    for url in urls:
        keyword_text = keyword_text.replace(url, " ")
    keyword_text = _normalise(keyword_text)

    flags: list[str] = []
    reasons: list[str] = []
    breakdown: list[RiskSignal] = []
    hit: set[str] = set()

    rule_based_score = 0

    # 1. Categories
    for cat in CATEGORIES:
        matches = _find(cat.regex, keyword_text)
        if matches:
            hit.add(cat.key)
            flags.append(cat.flag)
            reasons.append(cat.reason + ".")
            breakdown.append(RiskSignal(cat.key, cat.flag, cat.points, matches))
            rule_based_score += cat.points

    # 2. URLs
    if urls:
        findings = [inspect_url(u) for u in urls]
        # Any URL at all gets 15 points (base for suspicious_url = 30, but maybe just use inspect_url logic)
        # The user said SUSPICIOUS URL +30
        is_suspicious = any(f.points > 0 for f in findings)
        if is_suspicious:
            hit.add("suspicious_url")
            flags.append("Suspicious URL")
            reasons.append("It contains a suspicious URL.")
            breakdown.append(RiskSignal("suspicious_url", "Suspicious URL", 30, urls))
            rule_based_score += 30
        else:
            # Just a normal link
            hit.add("link")
            flags.append("Contains link")
            # Don't add to score, or maybe a small amount, user didn't specify normal link.
            # "LINK / CLICK REQUEST +15" is handled by suspicious_action mostly, or here.
            # Let's say normal link doesn't add points directly here unless it's suspicious action.

    # 3. Combinations
    combination_bonus = 0
    
    # "Detect combinations, not just individual keywords. Examples: reward + verification ..."
    def add_combo(name: str, pts: int, explanation: str):
        nonlocal combination_bonus
        combination_bonus += pts
        breakdown.append(RiskSignal("combination_bonus", name, pts))
        reasons.append(explanation)

    if "reward_lure" in hit and "verification_request" in hit:
        add_combo("Reward + Verification", 15, "It combines a reward lure with a verification request.")
    elif "reward_lure" in hit and "credential_request" in hit:
        add_combo("Reward + Credentials", 15, "It combines a reward lure with a credential request.")
    elif "account_suspension" in hit and "verification_request" in hit:
        add_combo("Account + Urgent Verification", 15, "It combines an account threat with an urgent verification request.")
    elif "financial_language" in hit and "otp_request" in hit:
        add_combo("Bank/Delivery + OTP", 15, "It asks for an OTP in a financial or service context.")
    elif "payment_request" in hit and "urgency" in hit:
        add_combo("Payment + Urgency", 15, "It combines a payment request with urgency.")
    
    # New contextual combinations
    if "account_action" in hit and "portal_action" in hit and "deadline_pressure" in hit:
        add_combo("Action + Portal + Deadline", 5, "It directs the user to a portal with a strict deadline.")
    if "account_action" in hit and "credential_request" in hit and "urgency" in hit:
        add_combo("Action + Credentials + Urgency", 20, "It pressures the user to provide credentials urgently.")
    if "financial_language" in hit and "credential_request" in hit and "suspicious_url" in hit:
        add_combo("Financial + Credentials + Link", 20, "It is a dangerous combination of financial context, credential requests, and a suspicious link.")

    return RiskAssessment(
        rule_based_score=rule_based_score,
        flags=flags,
        reasons=reasons,
        breakdown=breakdown,
        combination_bonus=combination_bonus
    )
