import pytest
import asyncio
from backend.services.ioc_extractor import extract_iocs
from backend.services.url_analyzer import analyze_url_local
from backend.services.threat_intel import aggregator
from backend.services.threat_intel.models import ProviderStatus
from backend.services.threat_intel.openphish import OpenPhishProvider

def test_ioc_extraction():
    text = "Check this out: https://example.com/login and http://192.168.1.1. Also email me at admin@test.com"
    iocs = extract_iocs(text)
    assert "admin@test.com" in iocs.emails
    assert "https://example.com/login" in iocs.urls
    assert "http://192.168.1.1" in iocs.urls
    assert "example.com" in iocs.domains
    assert "192.168.1.1" in iocs.ips

def test_url_analyzer_local():
    # Normal
    res = analyze_url_local("https://github.com/project")
    assert res.https is True
    assert res.raw_ip is False
    assert res.shortened is False
    assert res.suspicious_structure is False
    
    # Suspicious IP
    res = analyze_url_local("http://185.11.22.33/login")
    assert res.raw_ip is True
    assert res.suspicious_structure is True
    assert "Uses unencrypted HTTP" in res.signals
    
    # Shortener
    res = analyze_url_local("https://bit.ly/12345")
    assert res.shortened is True
    
    # Suspicious structure
    res = analyze_url_local("https://google.com@evil.xyz/login")
    assert res.suspicious_structure is True
    assert any("@" in s for s in res.signals)
    assert any(".xyz" in s for s in res.signals)

@pytest.mark.anyio
async def test_threat_intel_aggregator():
    # Because we don't have API keys set, they should return NOT_CONFIGURED
    # OpenPhish will try to fetch. Let's just check the structure.
    res = await aggregator.check_url("https://example.com", include_vt=True)
    assert res.url == "https://example.com"
    assert len(res.providers) == 4
    
    # Check caching
    res2 = await aggregator.check_url("https://example.com", include_vt=True)
    assert res is res2 or res.providers == res2.providers # Because it's cached in memory!

@pytest.mark.anyio
async def test_provider_failure_handling(monkeypatch):
    provider = OpenPhishProvider()
    
    async def mock_check_url(*args, **kwargs):
        raise ValueError("Simulated provider crash")
        
    monkeypatch.setattr(provider, "check_url", mock_check_url)
    
    # Aggregator should catch the exception and return ERROR status
    # Create a fresh aggregator to avoid cache
    from backend.services.threat_intel.aggregator import ThreatIntelAggregator
    test_agg = ThreatIntelAggregator()
    test_agg.providers = [provider]
    
    res = await test_agg.check_url("https://crash.com")
    assert len(res.providers) == 1
    assert res.providers[0].status == ProviderStatus.ERROR
    assert "Simulated provider crash" in res.providers[0].details
