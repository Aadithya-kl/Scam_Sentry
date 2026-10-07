import re
from urllib.parse import urlparse, unquote
from dataclasses import dataclass, field
from typing import List

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl", 
    "rebrand.ly", "tiny.cc", "cutt.ly"
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".pw", ".click", ".link", ".zip", ".mov"}

@dataclass
class UrlAnalysisResult:
    url: str
    domain: str
    https: bool = False
    raw_ip: bool = False
    shortened: bool = False
    punycode: bool = False
    excessive_subdomains: bool = False
    suspicious_structure: bool = False
    signals: List[str] = field(default_factory=list)
    risk_score: int = 0

def analyze_url_local(url: str) -> UrlAnalysisResult:
    res = UrlAnalysisResult(url=url, domain="")
    
    # basic inspection
    if "@" in url:
        res.suspicious_structure = True
        res.signals.append("Contains @ symbol (credential injection)")
        res.risk_score += 10
        
    if "%" in url:
        decoded = unquote(url)
        if decoded != url and "%" in decoded: # double encoded or similar
            res.signals.append("Suspicious URL encoding")
            res.risk_score += 5

    try:
        parsed = urlparse(url)
        res.https = (parsed.scheme == "https")
        if not res.https and parsed.scheme == "http":
            res.signals.append("Uses unencrypted HTTP")
            # HTTPS alone is neutral, but HTTP is slightly risky
            res.risk_score += 2

        netloc = parsed.netloc
        
        # Check port
        if ":" in netloc:
            host, port = netloc.split(":", 1)
            if port not in ("80", "443"):
                res.suspicious_structure = True
                res.signals.append(f"Unusual port {port}")
                res.risk_score += 10
        else:
            host = netloc
            
        res.domain = host
        
        # Check IP
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', host):
            res.raw_ip = True
            res.suspicious_structure = True
            res.signals.append("Raw IP address used as hostname")
            res.risk_score += 15
            
        # Check Punycode
        if "xn--" in host:
            res.punycode = True
            res.suspicious_structure = True
            res.signals.append("Punycode domain (homograph attack risk)")
            res.risk_score += 15
            
        # Check subdomains
        parts = host.split('.')
        if len(parts) > 4 and not res.raw_ip:
            res.excessive_subdomains = True
            res.suspicious_structure = True
            res.signals.append("Excessive subdomains")
            res.risk_score += 10
            
        # Check length
        if len(host) > 40:
            res.signals.append("Unusually long hostname")
            res.risk_score += 5
            
        # Check shortener
        # Extract base domain for shortener check (e.g. bit.ly)
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
        if base_domain.lower() in SHORTENERS:
            res.shortened = True
            res.signals.append("Shortened URL")
            res.risk_score += 10
            
        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if host.lower().endswith(tld):
                res.suspicious_structure = True
                res.signals.append(f"Suspicious TLD ({tld})")
                res.risk_score += 5
                
        # Path depth
        path_parts = [p for p in parsed.path.split('/') if p]
        if len(path_parts) > 5:
            res.signals.append("Excessive path depth")
            res.risk_score += 5
            
        # Query parameters
        if len(parsed.query) > 100:
            res.signals.append("Excessive query parameters")
            res.risk_score += 5
            
    except Exception as e:
        res.suspicious_structure = True
        res.signals.append("Malformed URL structure")
        res.risk_score += 10
        
    return res
