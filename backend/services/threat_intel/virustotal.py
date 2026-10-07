import os
import httpx
import base64
import time
import asyncio
from typing import Dict, Tuple, List
from urllib.parse import urlparse
from .base import ThreatIntelProvider
from .models import ThreatIntelResult, ProviderStatus

SENSITIVE_PARAMS = {"token", "auth", "password", "secret", "key", "session", "access_token", "signature", "sig"}
PRIVATE_HOSTS = {"localhost", "127.0.0.1"}

class VirusTotalProvider(ThreatIntelProvider):
    def __init__(self):
        self.cache: Dict[str, Tuple[float, ThreatIntelResult]] = {}
        self.cache_ttl = 3600 * 24 # 24 hours
        self._lock: asyncio.Lock = None
        self.last_requests: List[float] = []

    @property
    def rate_limit_lock(self):
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @property
    def name(self) -> str:
        return "VirusTotal"

    def is_private_or_sensitive(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if host in PRIVATE_HOSTS or host.startswith("192.168.") or host.startswith("10.") or host.startswith("172.16."):
                return True
            query = parsed.query.lower()
            for p in SENSITIVE_PARAMS:
                if f"{p}=" in query:
                    return True
        except:
            return True
        return False
        
    async def check_url(self, url: str) -> ThreatIntelResult:
        enabled = os.environ.get("VIRUSTOTAL_ENABLED", "false").lower() == "true"
        if not enabled:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.NOT_ENABLED)
            
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.NOT_CONFIGURED)
            
        if self.is_private_or_sensitive(url):
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.SKIPPED_FOR_PRIVACY)
            
        # Check cache
        now = time.time()
        if url in self.cache:
            ts, res = self.cache[url]
            if now - ts < self.cache_ttl:
                return res
                
        # Rate Limiting: 4 requests / minute
        async with self.rate_limit_lock:
            now = time.time()
            self.last_requests = [t for t in self.last_requests if now - t < 60]
            if len(self.last_requests) >= 4:
                return ThreatIntelResult(provider=self.name, status=ProviderStatus.RATE_LIMITED)
            self.last_requests.append(now)

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                headers = {"x-apikey": api_key}
                resp = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
                
                if resp.status_code == 401:
                    result = ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details="INVALID_CREDENTIALS")
                elif resp.status_code == 403:
                    result = ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details="FORBIDDEN")
                elif resp.status_code == 429:
                    result = ThreatIntelResult(provider=self.name, status=ProviderStatus.RATE_LIMITED)
                elif resp.status_code == 404:
                    result = ThreatIntelResult(provider=self.name, status=ProviderStatus.NO_MATCH, details="URL not found in VT dataset")
                elif resp.status_code >= 500:
                    result = ThreatIntelResult(provider=self.name, status=ProviderStatus.UNAVAILABLE, details="PROVIDER_ERROR")
                elif resp.status_code == 200:
                    data = resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0) + stats.get("undetected", 0)
                    
                    if malicious > 0 or suspicious > 0:
                        result = ThreatIntelResult(
                            provider=self.name, 
                            status=ProviderStatus.MATCH,
                            found=True,
                            threat_type="malware/phishing",
                            confidence="high" if malicious > 2 else "medium",
                            details=f"Malicious: {malicious}, Suspicious: {suspicious}",
                            indicator=url,
                            indicator_type="URL",
                            malicious_votes=malicious,
                            suspicious_votes=suspicious,
                            harmless_votes=harmless
                        )
                    else:
                        result = ThreatIntelResult(
                            provider=self.name, 
                            status=ProviderStatus.NO_MATCH,
                            indicator=url,
                            indicator_type="URL",
                            malicious_votes=malicious,
                            suspicious_votes=suspicious,
                            harmless_votes=harmless
                        )
                else:
                    result = ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details=f"HTTP {resp.status_code}")
                    
                self.cache[url] = (time.time(), result)
                return result
        except httpx.TimeoutException:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.TIMEOUT)
        except Exception as e:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details=str(e))
