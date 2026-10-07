import os
import json
import pytest
from backend.services.threat_intel.models import ProviderStatus
from backend.services.prediction_service import scan_url
from backend.services.threat_intel.aggregator import ThreatIntelAggregator
from backend.services.threat_intel.openphish import OpenPhishProvider
from backend.services.threat_intel.urlhaus import URLhausProvider
from backend.services.threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider
from backend.services.threat_intel.virustotal import VirusTotalProvider
import httpx

# Load fixtures
fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "threat_intel", "responses.json")
with open(fixture_path, "r") as f:
    MOCKS = json.load(f)

# Ensure keys are set for testing
os.environ["URLHAUS_AUTH_KEY"] = "mock"
os.environ["GOOGLE_SAFE_BROWSING_API_KEY"] = "mock"
os.environ["VIRUSTOTAL_ENABLED"] = "true"
os.environ["VIRUSTOTAL_API_KEY"] = "mock"

class MockResponse:
    def __init__(self, json_data, status_code=200):
        self.json_data = json_data
        self.status_code = status_code
        self.text = ""
    def json(self):
        return self.json_data

@pytest.fixture
def mock_httpx(monkeypatch):
    class MockClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
        async def get(self, url, *args, **kwargs):
            url = str(url)
            if "openphish.com" in url:
                if "mock-phishing.com" in url:
                    pass # We mock feed manually instead
                return MockResponse(None, 200)
            if "virustotal.com" in url:
                import base64
                url_id = url.split("/")[-1]
                try:
                    decoded = base64.urlsafe_b64decode(url_id + "==").decode()
                except:
                    decoded = ""
                if "mock-vt-match" in decoded:
                    return MockResponse(MOCKS["virustotal"]["MATCH"], 200)
                if "mock-timeout" in decoded:
                    raise httpx.TimeoutException("timeout")
                if "mock-ratelimit" in decoded:
                    return MockResponse({}, 429)
                return MockResponse(MOCKS["virustotal"]["NO_MATCH"], 200)
            return MockResponse(MOCKS["google_safe_browsing"]["NO_MATCH"], 200)

        async def post(self, url, *args, **kwargs):
            url = str(url)
            if "safebrowsing.googleapis" in url:
                if "mock-gsb-match" in kwargs.get("json", {}).get("threatInfo", {}).get("threatEntries", [{}])[0].get("url", ""):
                    return MockResponse(MOCKS["google_safe_browsing"]["MATCH"], 200)
                if "mock-timeout" in url:
                    raise httpx.TimeoutException("timeout")
                return MockResponse(MOCKS["google_safe_browsing"]["NO_MATCH"], 200)
                
            if "urlhaus-api.abuse.ch" in url:
                data = kwargs.get("data", {})
                if "mock-urlhaus-match" in data.get("url", ""):
                    return MockResponse(MOCKS["urlhaus"]["MATCH"], 200)
                if "mock-timeout" in data.get("url", ""):
                    raise httpx.TimeoutException("timeout")
                return MockResponse(MOCKS["urlhaus"]["NO_MATCH"], 200)
            return MockResponse({}, 200)

    monkeypatch.setattr(httpx, "AsyncClient", MockClient)
    
@pytest.fixture
def override_openphish_feed(monkeypatch):
    from backend.services.threat_intel.openphish_cache import openphish_cache
    openphish_cache.feed_urls = {"https://mock-phishing.com/login"}
    openphish_cache.status = "READY"
    openphish_cache.last_refresh = 9999999999.0

@pytest.mark.anyio
async def test_benign_url(mock_httpx, override_openphish_feed):
    res = await scan_url("https://benign.com")
    intel = res.threat_intelligence
    print("INTEL:", intel)
    assert res.prediction == "SAFE"
    assert all(i["status"] == "NO_MATCH" for i in intel)

@pytest.mark.anyio
async def test_phishing_match(mock_httpx, override_openphish_feed):
    res = await scan_url("https://mock-phishing.com/login")
    assert res.prediction == "SCAM"
    op_intel = next(i for i in res.threat_intelligence if i["provider"] == "OpenPhish")
    assert op_intel["status"] == "MATCH"

@pytest.mark.anyio
async def test_malware_match(mock_httpx, override_openphish_feed):
    res = await scan_url("https://mock-urlhaus-match.com/payload.exe")
    assert res.prediction == "SCAM"
    uh_intel = next(i for i in res.threat_intelligence if i["provider"] == "URLhaus")
    assert uh_intel["status"] == "MATCH"

@pytest.mark.anyio
async def test_provider_timeout(mock_httpx, override_openphish_feed):
    from backend.services.threat_intel.aggregator import aggregator
    aggregator.vt_provider.last_requests = []
    res = await scan_url("https://mock-timeout.com")
    vt_intel = next(i for i in res.threat_intelligence if i["provider"] == "VirusTotal")
    assert vt_intel["status"] == "TIMEOUT"

@pytest.mark.anyio
async def test_rate_limit(mock_httpx, override_openphish_feed):
    res = await scan_url("https://mock-ratelimit.com")
    vt_intel = next(i for i in res.threat_intelligence if i["provider"] == "VirusTotal")
    assert vt_intel["status"] == "RATE_LIMITED"
