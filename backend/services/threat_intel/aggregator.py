import asyncio
import time
from typing import List, Dict, Optional
from pydantic import BaseModel
from .base import ThreatIntelProvider
from .models import ThreatIntelResult, ProviderStatus
from .urlhaus import URLhausProvider
from .openphish import OpenPhishProvider
from .google_safe_browsing import GoogleSafeBrowsingProvider
from .virustotal import VirusTotalProvider

class UrlIntel(BaseModel):
    url: str
    providers: List[ThreatIntelResult]

class ThreatIntelAggregator:
    def __init__(self):
        self.providers: List[ThreatIntelProvider] = [
            URLhausProvider(),
            OpenPhishProvider(),
            GoogleSafeBrowsingProvider()
        ]
        self.vt_provider = VirusTotalProvider()
        
        # Very simple in-memory cache: url -> (timestamp, list of results)
        self.cache: Dict[str, tuple[float, List[ThreatIntelResult]]] = {}
        self.cache_ttl = 3600 # 1 hour
        
    async def check_url(self, url: str, include_vt: bool = False) -> UrlIntel:
        import os
        from .models import ProviderStatus
        
        # DEMO MODE
        if os.environ.get("DEMO_MODE", "false").lower() == "true" and os.environ.get("ENVIRONMENT", "development").lower() != "production":
            if "demo-safe.com" in url:
                return UrlIntel(url=url, providers=[ThreatIntelResult(provider="Demo", status=ProviderStatus.NO_MATCH)])
            elif "demo-scam.com" in url:
                return UrlIntel(url=url, providers=[ThreatIntelResult(provider="Demo", status=ProviderStatus.MATCH, found=True, threat_type="phishing")])
                
        now = time.time()
        
        # We don't cache include_vt because VT is optional. We will just run VT if needed.
        # Check cache for base providers
        results_from_cache = None
        if url in self.cache:
            ts, results = self.cache[url]
            if now - ts < self.cache_ttl:
                results_from_cache = results

        if results_from_cache is None:
            # Run concurrently for base providers
            tasks = [p.check_url(url) for p in self.providers]
            base_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            valid_results = []
            for i, res in enumerate(base_results):
                if isinstance(res, Exception):
                    valid_results.append(ThreatIntelResult(
                        provider=self.providers[i].name,
                        status="ERROR",
                        details=str(res)
                    ))
                else:
                    valid_results.append(res)
            
            self.cache[url] = (now, valid_results)
            results_from_cache = valid_results
            
        final_results = list(results_from_cache)
        
        if include_vt:
            vt_res = await self.vt_provider.check_url(url)
            final_results.append(vt_res)
        
        return UrlIntel(url=url, providers=final_results)
        
    async def check_urls(self, urls: List[str]) -> List[UrlIntel]:
        tasks = [self.check_url(url, include_vt=False) for url in urls]
        return await asyncio.gather(*tasks)

aggregator = ThreatIntelAggregator()
