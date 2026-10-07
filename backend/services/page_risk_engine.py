from typing import List, Dict, Any
import asyncio
import time
import os
import logging
from backend.services.prediction_service import analyze_url_local
from backend.services.threat_intel.aggregator import ThreatIntelAggregator

logger = logging.getLogger("scamsentry")

class PageRiskEngine:
    def __init__(self):
        self.intel_aggregator = ThreatIntelAggregator()

    async def analyze_page(self, page_url: str, links: List[str]) -> Dict[str, Any]:
        # Limit to 50 links maximum for performance
        MAX_LINKS = 50
        analyzed_links = links[:MAX_LINKS]
        
        # Parallelize the analysis of links (Base Providers)
        async def analyze_single_link(link: str):
            # Local URL analysis
            local_features = analyze_url_local(link)
            local_score = local_features.risk_score
            
            # Threat intel check (NO VirusTotal yet)
            intel_results = await self.intel_aggregator.check_url(link, include_vt=False)
            
            # Link-level fusion
            intel_score = 0
            has_match = False
            for i in intel_results.providers:
                status = getattr(i.status, "value", i.status) if hasattr(i, "status") else i.get("status") if isinstance(i, dict) else None
                if status == "MATCH":
                    has_match = True
                    intel_score += 80
                    
            final_link_score = min(100, local_score + intel_score)
            
            return {
                "url": link,
                "local_score": local_score,
                "intel_results": [i.model_dump() if hasattr(i, "model_dump") else dict(i) for i in intel_results.providers],
                "risk_score": final_link_score,
                "is_threat": has_match
            }

        tasks = [analyze_single_link(link) for link in analyzed_links]
        link_analyses = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_analyses = []
        for r in link_analyses:
            if isinstance(r, Exception):
                logger.error(f"[PAGE SCANNER] Link analysis failed: {r}")
            else:
                valid_analyses.append(r)
                
        # --- VIRUSTOTAL PRIORITIZATION ---
        vt_enabled = os.environ.get("VIRUSTOTAL_ENABLED", "false").lower() == "true"
        if vt_enabled and valid_analyses:
            try:
                vt_limit = int(os.environ.get("VT_LOOKUPS_PER_PAGE", "1"))
            except ValueError:
                vt_limit = 1
                
            if vt_limit > 0:
                # Prioritize: 
                # 1. URLs already flagged suspicious locally or by other intel (high risk_score)
                # We sort by risk_score DESC
                valid_analyses.sort(key=lambda x: x["risk_score"], reverse=True)
                
                # Pick top N URLs that aren't already definitively threats (optional, but good to find hidden threats)
                # Actually, the user specifically says:
                # 1. URLs already flagged suspicious locally
                # 2. URLs flagged by another threat-intelligence provider
                # 3. URLs with suspicious structure
                
                for i in range(min(vt_limit, len(valid_analyses))):
                    target = valid_analyses[i]
                    url = target["url"]
                    
                    try:
                        vt_res = await self.intel_aggregator.vt_provider.check_url(url)
                        target["intel_results"].append(vt_res.model_dump() if hasattr(vt_res, "model_dump") else dict(vt_res))
                        
                        status = getattr(vt_res.status, "value", vt_res.status) if hasattr(vt_res, "status") else (vt_res.get("status") if isinstance(vt_res, dict) else None)
                        if status == "MATCH":
                            target["is_threat"] = True
                            # Boost risk score safely without double counting
                            target["risk_score"] = min(100, target["risk_score"] + 80)
                    except Exception as e:
                        logger.error(f"[VIRUSTOTAL PAGE SCAN] Error checking {url}: {e}")
                
        # Page-level fusion
        clean_count = 0
        suspicious_count = 0
        threat_count = 0
        
        max_link_score = 0
        for r in valid_analyses:
            score = r["risk_score"]
            max_link_score = max(max_link_score, score)
            if r["is_threat"]:
                threat_count += 1
            elif score >= 50:
                suspicious_count += 1
            else:
                clean_count += 1
                
        # Base page score on the highest risk link, but boost it if there are multiple suspicious links
        page_risk_score = max_link_score
        if threat_count > 0:
            page_risk_score = max(page_risk_score, 90)
        elif suspicious_count > 2:
            page_risk_score = min(100, page_risk_score + (suspicious_count * 5))
            
        if page_risk_score >= 75:
            risk_level = "CRITICAL"
            prediction = "SCAM" if threat_count > 0 else "SUSPICIOUS"
        elif page_risk_score >= 50:
            risk_level = "HIGH"
            prediction = "SUSPICIOUS"
        elif page_risk_score >= 25:
            risk_level = "MEDIUM"
            prediction = "SUSPICIOUS"
        else:
            risk_level = "LOW"
            prediction = "SAFE"
            
        # Top notable links
        sorted_links = sorted(valid_analyses, key=lambda x: x["risk_score"], reverse=True)
        notable_links = sorted_links[:5]
        
        formatted_notables = []
        for nl in notable_links:
            matches = [i["provider"] for i in nl["intel_results"] if i["status"] == "MATCH"]
            reason = "Threat Match: " + ", ".join(matches) if matches else ("Suspicious Structure" if nl["local_score"] >= 40 else "Low Risk")
            
            nl_risk = "SCAM" if nl["is_threat"] else ("SUSPICIOUS" if nl["risk_score"] >= 50 else "LOW RISK")
            
            formatted_notables.append({
                "url": nl["url"],
                "prediction": nl_risk,
                "risk_score": nl["risk_score"],
                "reason": reason
            })
            
        return {
            "page_url": page_url,
            "total_links_found": len(links),
            "links_analyzed": len(analyzed_links),
            "external_links": len(links), # Assuming the extension already filtered them
            "summary": {
                "clean": clean_count,
                "suspicious": suspicious_count,
                "threats": threat_count
            },
            "risk_score": page_risk_score,
            "risk_level": risk_level,
            "prediction": prediction,
            "notable_links": formatted_notables
        }

page_risk_engine = PageRiskEngine()
