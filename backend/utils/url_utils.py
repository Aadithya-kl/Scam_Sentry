"""URL extraction and heuristic URL inspection.

These checks are intentionally simple and offline (no reputation lookups).
Each finding carries a fixed number of points so the overall risk score is
fully explainable.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")

# Explicit URLs, www. links and bare domains such as "secure-login.xyz/verify".
_URL_RE = re.compile(
    r"""(
        https?://[^\s<>"']+
      | www\.[^\s<>"']+
      | \b(?:[a-z0-9-]+\.)+(?:com|net|org|info|biz|co|io|ly|me|uk|in|xyz|top|click|link|
          online|site|live|ru|cn|tk|ml|ga|cf|gq|zip|mov|support|help|win|icu|vip|shop)
        \b(?:/[^\s<>"']*)?
    )""",
    re.IGNORECASE | re.VERBOSE,
)

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly", "bit.do", "v.gd",
})

# TLDs that are cheap/free and disproportionately used in phishing campaigns.
RISKY_TLDS = frozenset({
    "xyz", "top", "click", "link", "online", "site", "live", "ru", "cn", "tk", "ml",
    "ga", "cf", "gq", "zip", "mov", "support", "help", "win", "icu", "vip", "shop",
})

# Words that phishing domains commonly embed to look trustworthy.
DECEPTIVE_DOMAIN_WORDS = (
    "login", "signin", "verify", "verification", "secure", "account", "update",
    "banking", "wallet", "support", "unlock", "confirm", "kyc", "reward", "claim",
)

MAX_SUBDOMAINS = 3
MAX_PATH_SEGMENTS = 4
MAX_URL_LENGTH = 75


@dataclass
class UrlFinding:
    """Result of inspecting a single URL."""

    url: str
    host: str
    points: int = 0
    issues: list[str] = field(default_factory=list)

    def add(self, points: int, issue: str) -> None:
        self.points += points
        self.issues.append(issue)


def extract_urls(text: str) -> list[str]:
    """Return all URL-like substrings, stripped of trailing punctuation."""
    text = _EMAIL_RE.sub(" ", text)  # "help@bank.com" is an address, not a link
    urls = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:!?)]}'\"")
        if url and url not in urls:
            urls.append(url)
    return urls


def _host_of(url: str) -> tuple[str, str, str]:
    """Return (scheme, host, path) for a URL that may lack a scheme."""
    parsed = urlsplit(url if re.match(r"^https?://", url, re.I) else f"//{url}")
    return (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.path or "")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def inspect_url(url: str) -> UrlFinding:
    """Apply transparent heuristics to a single URL."""
    scheme, host, path = _host_of(url)
    finding = UrlFinding(url=url, host=host)

    if scheme == "http":
        finding.add(10, "uses insecure http:// instead of https://")
    if _is_ip(host):
        finding.add(20, "points to a raw IP address instead of a domain name")
        return finding

    if host.startswith("www."):
        host = host[4:]
    if host in URL_SHORTENERS:
        finding.add(15, "uses a link shortener that hides the real destination")

    labels = host.split(".")
    tld = labels[-1] if labels else ""
    if tld in RISKY_TLDS:
        finding.add(10, f"uses a high-risk top-level domain (.{tld})")
    if len(labels) - 2 >= MAX_SUBDOMAINS:
        finding.add(5, "has an unusually deep chain of subdomains")
    if host.count("-") >= 2:
        finding.add(5, "has a hyphen-heavy domain name, common in look-alike sites")

    deceptive = [w for w in DECEPTIVE_DOMAIN_WORDS if w in host]
    if deceptive:
        finding.add(10, f"embeds trust words in the domain ('{deceptive[0]}')")

    segments = [s for s in path.split("/") if s]
    if len(segments) > MAX_PATH_SEGMENTS or len(url) > MAX_URL_LENGTH:
        finding.add(5, "has an excessively long or deep URL path")

    return finding
