import re
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

@dataclass
class IOCs:
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)

# basic regexes
URL_REGEX = re.compile(r'(?i)\b(?:https?://|www\.)[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/))')
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

def extract_iocs(text: str) -> IOCs:
    iocs = IOCs()
    
    # Extract emails
    iocs.emails = list(set(EMAIL_REGEX.findall(text)))
    
    # Extract URLs
    url_matches = [m.group(0) for m in re.finditer(r'(?i)\b(?:https?://|www\.)[a-zA-Z0-9./_?&=-]+', text)]
    
    # clean up matched URLs
    cleaned_urls = []
    for u in url_matches:
        u = u.rstrip(".,;:\"'()<>")
        if u.startswith('www.'):
            u = 'http://' + u
        cleaned_urls.append(u)
    
    iocs.urls = list(set(cleaned_urls))
    
    # Extract Domains & IPs from URLs
    for url in iocs.urls:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.split(':')[0] # remove port
            if netloc:
                if IP_REGEX.match(netloc):
                    if netloc not in iocs.ips:
                        iocs.ips.append(netloc)
                else:
                    if netloc not in iocs.domains:
                        iocs.domains.append(netloc)
        except Exception:
            pass
            
    # Also find loose IPs not in URLs
    loose_ips = IP_REGEX.findall(text)
    for ip in loose_ips:
        if ip not in iocs.ips:
            iocs.ips.append(ip)
            
    return iocs
