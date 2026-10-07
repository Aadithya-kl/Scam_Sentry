import pytest
import os
import json
from backend.services.page_risk_engine import page_risk_engine
from backend.services.threat_intel.models import ProviderStatus
from backend.services.threat_intel.openphish_cache import openphish_cache

@pytest.fixture
def dummy_cache():
    openphish_cache.feed_urls = {"https://phishing.example.com/login"}
    openphish_cache.last_refresh = 1.0
    openphish_cache.status = "READY"
    openphish_cache.initialized = True
    yield
    openphish_cache.feed_urls = set()

@pytest.mark.anyio
async def test_normal_page(dummy_cache):
    # Fixture A: normal page, 20 ordinary links
    links = [f"https://example.com/page{i}" for i in range(20)]
    res = await page_risk_engine.analyze_page("https://example.com", links)
    assert res["prediction"] == "SAFE"
    assert res["risk_level"] == "LOW"
    assert res["summary"]["threats"] == 0
    assert res["total_links_found"] == 20

@pytest.mark.anyio
async def test_shortened_urls(dummy_cache, monkeypatch):
    # Fixture B: page with several shortened URLs
    from backend.services.url_analyzer import UrlAnalysisResult
    def mock_analyze(url):
        r = UrlAnalysisResult(url=url, domain="domain")
        if "bit.ly" in url or "t.co" in url or "tinyurl.com" in url:
            r.risk_score = 60
        else:
            r.risk_score = 0
        return r
    monkeypatch.setattr("backend.services.page_risk_engine.analyze_url_local", mock_analyze)
    
    links = ["https://bit.ly/123", "https://t.co/abc", "https://tinyurl.com/xyz", "https://example.com"]
    res = await page_risk_engine.analyze_page("https://example.com", links)
    assert res["prediction"] == "SUSPICIOUS"
    assert res["summary"]["suspicious"] >= 3

@pytest.mark.anyio
async def test_phishing_match(dummy_cache, monkeypatch):
    # Fixture C: page with one mocked phishing match
    links = ["https://example.com/safe", "https://phishing.example.com/login", "https://example.com/about"]
    res = await page_risk_engine.analyze_page("https://example.com", links)
    print("res", res)
    assert res["prediction"] == "SCAM"
    assert res["risk_level"] == "CRITICAL"
    assert res["summary"]["threats"] == 1
    
@pytest.mark.anyio
async def test_bounded_analysis(dummy_cache):
    # Fixture D: page with 50+ links
    links = [f"https://example.com/page{i}" for i in range(100)]
    res = await page_risk_engine.analyze_page("https://example.com", links)
    assert res["total_links_found"] == 100
    assert res["links_analyzed"] == 50
