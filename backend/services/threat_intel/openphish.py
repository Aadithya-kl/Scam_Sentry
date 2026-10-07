from .base import ThreatIntelProvider
from .models import ThreatIntelResult, ProviderStatus
from .openphish_cache import openphish_cache

class OpenPhishProvider(ThreatIntelProvider):
    @property
    def name(self) -> str:
        return "OpenPhish"
        
    async def check_url(self, url: str) -> ThreatIntelResult:
        health = openphish_cache.get_health()
        
        if not health["cache_loaded"]:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.ERROR, details="Cache empty or unavailable")
            
        is_match = openphish_cache.check_url(url)
        
        if is_match:
            return ThreatIntelResult(
                provider=self.name, 
                status=ProviderStatus.MATCH,
                found=True,
                threat_type="phishing",
                confidence="high"
            )
        else:
            return ThreatIntelResult(provider=self.name, status=ProviderStatus.NO_MATCH)
