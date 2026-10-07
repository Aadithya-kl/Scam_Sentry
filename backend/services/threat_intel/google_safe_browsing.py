import os
import httpx
from .base import ThreatIntelProvider
from .models import ThreatIntelResult, ProviderStatus

class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    @property
    def name(self) -> str:
        return "Google Safe Browsing"
        
    async def check_url(self, url: str) -> ThreatIntelResult:
        api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
        if not api_key:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.NOT_CONFIGURED)
            
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                payload = {
                    "client": {
                        "clientId": "scamsentry",
                        "clientVersion": "1.0.0"
                    },
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                
                resp = await client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                    json=payload
                )
                
                if resp.status_code == 429:
                    return ThreatIntelResult(provider=self.name, status=ProviderStatus.RATE_LIMITED)
                elif resp.status_code == 200:
                    res = resp.json()
                    matches = res.get("matches", [])
                    if matches:
                        threat_types = list(set([m.get("threatType") for m in matches]))
                        return ThreatIntelResult(
                            provider=self.name, 
                            status=ProviderStatus.MATCH,
                            found=True,
                            threat_type=",".join(threat_types),
                            confidence="high",
                            details=f"Matched threat types: {', '.join(threat_types)}"
                        )
                    else:
                        return ThreatIntelResult(provider=self.name, status=ProviderStatus.NO_MATCH)
                else:
                    return ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details=f"HTTP {resp.status_code}")
        except httpx.TimeoutException:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.TIMEOUT)
        except Exception as e:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details=str(e))
