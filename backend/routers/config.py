import os
import time
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict
from backend.services.threat_intel.openphish_cache import openphish_cache
from backend.services.threat_intel.openphish import OpenPhishProvider
from backend.services.threat_intel.urlhaus import URLhausProvider
from backend.services.threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider
from backend.services.threat_intel.virustotal import VirusTotalProvider

router = APIRouter()

class ProviderConfigDetail(BaseModel):
    enabled: bool
    configured: bool
    status: str

class ProvidersResponse(BaseModel):
    providers: Dict[str, ProviderConfigDetail]

class TestResult(BaseModel):
    provider: str
    status: str
    latency: str
    error: str = None

@router.get("/providers", response_model=ProvidersResponse, tags=["system"])
def get_providers():
    op_health = openphish_cache.get_health()
    
    return {
        "providers": {
            "urlhaus": {
                "enabled": True,
                "configured": bool(os.environ.get("URLHAUS_AUTH_KEY")),
                "status": "READY" if os.environ.get("URLHAUS_AUTH_KEY") else "NOT CONFIGURED"
            },
            "openphish": {
                "enabled": True,
                "configured": True,
                "status": op_health["status"]
            },
            "google_safe_browsing": {
                "enabled": True,
                "configured": bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")),
                "status": "READY" if os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY") else "NOT CONFIGURED"
            },
            "virustotal": {
                "enabled": os.environ.get("VIRUSTOTAL_ENABLED", "false").lower() == "true",
                "configured": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
                "status": "DISABLED" if os.environ.get("VIRUSTOTAL_ENABLED", "false").lower() != "true" else ("READY" if os.environ.get("VIRUSTOTAL_API_KEY") else "NOT CONFIGURED")
            }
        }
    }

@router.post("/providers/test", response_model=list[TestResult], tags=["system"])
async def test_providers():
    results = []
    
    # OpenPhish
    start = time.time()
    try:
        health = openphish_cache.get_health()
        if health["cache_loaded"]:
            results.append({
                "provider": "OpenPhish", 
                "status": health["status"], 
                "latency": f"{int((time.time() - start) * 1000)}ms",
                "details": f"Feed Age: {health['feed_age_minutes']}m"
            })
        else:
            results.append({"provider": "OpenPhish", "status": "ERROR", "latency": f"{int((time.time() - start) * 1000)}ms", "error": "Feed empty or unreachable"})
    except Exception as e:
        results.append({"provider": "OpenPhish", "status": "ERROR", "latency": f"{int((time.time() - start) * 1000)}ms", "error": str(e)})

    # URLhaus
    start = time.time()
    if os.environ.get("URLHAUS_AUTH_KEY"):
        try:
            uh = URLhausProvider()
            res = await uh.check_url("https://example.com") # Safe test URL
            if res.status in ["NO_MATCH", "MATCH", "CHECKED"]:
                results.append({"provider": "URLhaus", "status": "READY", "latency": f"{int((time.time() - start) * 1000)}ms"})
            else:
                results.append({"provider": "URLhaus", "status": "ERROR", "latency": f"{int((time.time() - start) * 1000)}ms", "error": res.details})
        except Exception as e:
            results.append({"provider": "URLhaus", "status": "ERROR", "latency": f"{int((time.time() - start) * 1000)}ms", "error": str(e)})
    else:
        results.append({"provider": "URLhaus", "status": "NOT CONFIGURED", "latency": "0ms"})

    # Google Safe Browsing
    start = time.time()
    if os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"):
        try:
            gsb = GoogleSafeBrowsingProvider()
            res = await gsb.check_url("https://example.com") # Safe test URL
            if res.status in ["NO_MATCH", "MATCH", "CHECKED"]:
                results.append({"provider": "Google Safe Browsing", "status": "READY", "latency": f"{int((time.time() - start) * 1000)}ms"})
            else:
                results.append({"provider": "Google Safe Browsing", "status": "ERROR", "latency": f"{int((time.time() - start) * 1000)}ms", "error": res.details})
        except Exception as e:
            results.append({"provider": "Google Safe Browsing", "status": "ERROR", "latency": f"{int((time.time() - start) * 1000)}ms", "error": str(e)})
    else:
        results.append({"provider": "Google Safe Browsing", "status": "NOT CONFIGURED", "latency": "0ms"})

    # VirusTotal
    start = time.time()
    if os.environ.get("VIRUSTOTAL_ENABLED", "false").lower() == "true":
        if os.environ.get("VIRUSTOTAL_API_KEY"):
            # To preserve public quota (4/min), we just report READY if configured.
            results.append({"provider": "VirusTotal", "status": "READY", "latency": "0ms", "details": "Configuration validated (Skipped live test to preserve quota)"})
        else:
            results.append({"provider": "VirusTotal", "status": "NOT CONFIGURED", "latency": "0ms"})
    else:
        results.append({"provider": "VirusTotal", "status": "DISABLED", "latency": "0ms"})

    return results
