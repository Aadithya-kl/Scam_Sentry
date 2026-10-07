import pytest
import os
import asyncio
from unittest.mock import patch, MagicMock
from backend.services.threat_intel.virustotal import VirusTotalProvider
from backend.services.threat_intel.models import ProviderStatus

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.fixture
def provider():
    return VirusTotalProvider()

@pytest.mark.anyio
async def test_virustotal_disabled(provider, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "false")
    res = await provider.check_url("https://example.com")
    assert res.status == ProviderStatus.NOT_ENABLED

@pytest.mark.anyio
async def test_virustotal_missing_key(provider, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "true")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    res = await provider.check_url("https://example.com")
    assert res.status == ProviderStatus.NOT_CONFIGURED

@pytest.mark.anyio
async def test_virustotal_privacy_skip(provider, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")
    
    # Internal IP
    res = await provider.check_url("http://192.168.1.10/admin")
    assert res.status == ProviderStatus.SKIPPED_FOR_PRIVACY
    
    # Sensitive param
    res = await provider.check_url("https://example.com/reset?token=123")
    assert res.status == ProviderStatus.SKIPPED_FOR_PRIVACY

@pytest.mark.anyio
@patch("httpx.AsyncClient.get")
async def test_virustotal_rate_limit(mock_get, provider, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")
    
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.return_value = mock_resp
    
    res = await provider.check_url("https://example.com")
    assert res.status == ProviderStatus.RATE_LIMITED

@pytest.mark.anyio
@patch("httpx.AsyncClient.get")
async def test_virustotal_no_report(mock_get, provider, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")
    
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp
    
    res = await provider.check_url("https://example.com/new")
    assert res.status == ProviderStatus.NO_MATCH
    assert "URL not found" in res.details

@pytest.mark.anyio
@patch("httpx.AsyncClient.get")
async def test_virustotal_malicious_report(mock_get, provider, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 4,
                    "harmless": 60,
                    "undetected": 10
                }
            }
        }
    }
    mock_get.return_value = mock_resp
    
    res = await provider.check_url("https://malicious.com")
    assert res.status == ProviderStatus.MATCH
    assert res.malicious_votes == 12
    assert res.suspicious_votes == 4
    assert res.harmless_votes == 70

@pytest.mark.anyio
@patch("httpx.AsyncClient.get")
async def test_virustotal_caching(mock_get, provider, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")
    
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp
    
    res1 = await provider.check_url("https://cache-test.com")
    res2 = await provider.check_url("https://cache-test.com")
    
    # Ensure httpx.get was only called once
    assert mock_get.call_count == 1
    assert res1.status == ProviderStatus.NO_MATCH
    assert res2.status == ProviderStatus.NO_MATCH

@pytest.mark.anyio
async def test_virustotal_local_rate_limiter(provider, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")
    
    # Fill up requests
    import time
    now = time.time()
    provider.last_requests = [now, now, now, now]
    
    res = await provider.check_url("https://example.com/ratelimit")
    assert res.status == ProviderStatus.RATE_LIMITED
