import os
import httpx
from .base import ThreatIntelProvider
from .models import ThreatIntelResult, ProviderStatus

class URLhausProvider(ThreatIntelProvider):
    @property
    def name(self) -> str:
        return "URLhaus"
        
    async def check_url(self, url: str) -> ThreatIntelResult:
        api_key = os.environ.get("URLHAUS_AUTH_KEY")
        if not api_key:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.NOT_CONFIGURED)
            
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                data = {'url': url}
                headers = {'Auth-Key': api_key}
                resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data=data, headers=headers)
                
                if resp.status_code == 429:
                    return ThreatIntelResult(provider=self.name, status=ProviderStatus.RATE_LIMITED)
                elif resp.status_code == 403:
                    try:
                        res = resp.json()
                        return ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details=res.get("query_status", "Forbidden"))
                    except:
                        return ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details="Forbidden (Invalid API Key)")
                elif resp.status_code == 200:
                    res = resp.json()
                    if res.get("query_status") == "ok":
                        return ThreatIntelResult(
                            provider=self.name, 
                            status=ProviderStatus.MATCH,
                            found=True,
                            threat_type="malware",
                            confidence="high",
                            details="Matched in URLhaus malware database."
                        )
                    elif res.get("query_status") == "no_results":
                        return ThreatIntelResult(provider=self.name, status=ProviderStatus.NO_MATCH)
                    else:
                        return ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details=res.get("query_status"))
                else:
                    return ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR)
        except httpx.TimeoutException:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.TIMEOUT)
        except Exception as e:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details=str(e))
