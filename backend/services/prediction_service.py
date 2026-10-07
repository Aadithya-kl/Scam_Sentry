"""Prediction service combining ML and heuristic rule engines with Threat Intel."""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

from backend.services import risk_engine
from backend.services.model_service import ModelService
from ml.inference import TermContribution
from backend.services.ioc_extractor import extract_iocs, IOCs
from backend.services.url_analyzer import analyze_url_local, UrlAnalysisResult
from backend.services.threat_intel import aggregator
import logging

logger = logging.getLogger("scamsentry")

@dataclass
class PredictionResult:
    prediction: str
    confidence: float
    spam_probability: float
    risk_score: int
    risk_level: str
    flags: list[str]
    explanation: list[str]
    top_terms: list[TermContribution]
    score_breakdown: dict
    iocs: dict
    url_analysis: list[dict]
    threat_intelligence: list[dict]

async def predict(text: str, model: ModelService) -> PredictionResult:
    p_spam = model.spam_probability(text)
    risk = risk_engine.analyze(text)

    # 1. Base score from ML (0-30)
    base_score = int(p_spam * 30)

    # 2. IOC Extraction
    iocs = extract_iocs(text)
    
    for u in iocs.urls:
        logger.info(f"[IOC] URL extracted: {u}")
        
    # 3. Local URL Analysis (0-20)
    url_analysis_results = [analyze_url_local(u) for u in iocs.urls]
    url_score = sum([u.risk_score for u in url_analysis_results])
    url_score = min(20, url_score)
    for res in url_analysis_results:
        logger.info(f"[URL ANALYZER] Structural risk score for {res.url}: {res.risk_score}")

    # 4. Threat Intel (0-50)
    intel_results = await aggregator.check_urls(iocs.urls)
    
    threat_intelligence = []
    intel_score = 0
    intel_flags = set()
    intel_reasons = []
    
    for intel in intel_results:
        for p in intel.providers:
            logger.info(f"[{p.provider.upper()}] Status for {intel.url}: {p.status}")
            threat_intelligence.append({
                "url": intel.url,
                "provider": p.provider,
                "status": p.status,
                "threat_type": p.threat_type
            })
            if p.found and p.status == "MATCH":
                intel_score += 30 # Just one match is enough to heavily bump score
                if p.provider == "URLhaus":
                    intel_flags.add("Malware URL Match")
                    intel_reasons.append(f"URLhaus reported {intel.url} as malware distribution.")
                elif p.provider == "OpenPhish":
                    intel_flags.add("Phishing URL Match")
                    intel_reasons.append(f"OpenPhish reported {intel.url} as a phishing site.")
                elif p.provider == "Google Safe Browsing":
                    intel_flags.add("Safe Browsing Threat")
                    intel_reasons.append(f"Google Safe Browsing reported {intel.url} as {p.threat_type}.")
                elif p.provider == "VirusTotal":
                    intel_flags.add("VirusTotal Threat")
                    intel_reasons.append(f"VirusTotal reported {intel.url} as malicious/suspicious.")

    intel_score = min(50, intel_score)

    # 5. Total Risk Calculation
    raw_risk_score = base_score + risk.rule_based_score + risk.combination_bonus + url_score + intel_score
    risk_score = max(0, min(100, raw_risk_score))
    logger.info(f"[RISK FUSION] Final score: {risk_score}")

    # 6. Flags & Explanations
    flags = list(risk.flags)
    explanation = list(risk.reasons)

    for u in url_analysis_results:
        for sig in u.signals:
            if sig not in flags:
                flags.append(sig)
    
    flags.extend(list(intel_flags))
    explanation.extend(intel_reasons)
    
    if p_spam >= 0.5:
        explanation.insert(0, f"The machine learning model detected spam-like wording ({p_spam:.0%} probability).")
    elif not explanation:
        explanation.append("No common scam indicators or spam patterns were detected.")

    # 7. Overrides
    categories_hit = {s.category for s in risk.breakdown}
    has_credentials = "credential_request" in categories_hit or "otp_request" in categories_hit
    has_download = "suspicious_action" in categories_hit
    override_scam = False
    
    if (
        (has_credentials and "verification_request" in categories_hit) or
        ("suspicious_url" in categories_hit and has_credentials) or
        ("reward_lure" in categories_hit and "verification_request" in categories_hit) or
        ("financial_language" in categories_hit and "urgency" in categories_hit) or
        ("account_action" in categories_hit and has_credentials and "urgency" in categories_hit) or
        ("financial_language" in categories_hit and has_credentials and "suspicious_url" in categories_hit)
    ):
        override_scam = True

    # New Threat Intel Overrides
    if "Phishing URL Match" in intel_flags and has_credentials:
        override_scam = True
    if "Malware URL Match" in intel_flags and has_download:
        override_scam = True
    if "Phishing URL Match" in intel_flags and "verification_request" in categories_hit:
        override_scam = True
        
    if override_scam and risk_score < 75:
        risk_score = 75

    # 8. Classification Thresholds
    if risk_score <= 24:
        prediction = "SAFE"
        risk_level = "LOW"
    elif risk_score <= 49:
        prediction = "SUSPICIOUS"
        risk_level = "MEDIUM"
    elif risk_score <= 74:
        prediction = "SPAM"
        risk_level = "HIGH"
    else:
        prediction = "SCAM"
        risk_level = "CRITICAL"

    if prediction in ("SAFE", "SUSPICIOUS") and p_spam >= 0.5:
        prediction = "SPAM"
        risk_level = "MEDIUM"
        if risk_score < 50:
            risk_score = 50

    if prediction == "SCAM":
        confidence = min(1.0, 0.5 + (risk_score - 75) / 50.0)
    elif prediction == "SPAM":
        confidence = p_spam
    elif prediction == "SUSPICIOUS":
        confidence = 0.5 + (risk_score - 25) / 50.0
    else:
        confidence = 1.0 - (risk_score / 24.0)
        confidence = max(0.0, min(1.0, confidence))

    # 9. Score Breakdown
    score_breakdown = {
        "spam_probability_score": base_score,
        "combination_bonus": risk.combination_bonus,
        "url_structural_risk": url_score,
        "threat_intel_score": intel_score
    }
    for item in risk.breakdown:
        if item.category != "combination_bonus":
            score_breakdown[item.category] = item.points

    top_terms = model.top_terms(text) if p_spam >= 0.5 else []

    return PredictionResult(
        prediction=prediction,
        confidence=round(confidence, 4),
        spam_probability=round(p_spam, 4),
        risk_score=risk_score,
        risk_level=risk_level,
        flags=flags,
        explanation=explanation,
        top_terms=top_terms,
        score_breakdown=score_breakdown,
        iocs=asdict(iocs),
        url_analysis=[asdict(u) for u in url_analysis_results],
        threat_intelligence=threat_intelligence
    )

async def scan_url(url: str) -> PredictionResult:
    logger.info(f"[IOC] URL extracted: {url}")
    
    # 1. Local URL Analysis (0-50 for pure URL scan to give it weight without text)
    url_analysis_result = analyze_url_local(url)
    logger.info(f"[URL ANALYZER] Structural risk score: {url_analysis_result.risk_score}")
    
    # Scale URL structure score up slightly since we don't have text ML
    url_score = url_analysis_result.risk_score * 2
    url_score = min(50, url_score)
    
    # 2. Threat Intel (0-50)
    intel_result = await aggregator.check_url(url, include_vt=True)
    
    threat_intelligence = []
    intel_score = 0
    intel_flags = set()
    intel_reasons = []
    
    for p in intel_result.providers:
        logger.info(f"[{p.provider.upper()}] Status: {p.status}")
        threat_intelligence.append({
            "url": intel_result.url,
            "provider": p.provider,
            "status": p.status,
            "threat_type": p.threat_type
        })
        if p.found and p.status == "MATCH":
            intel_score += 40
            if p.provider == "URLhaus":
                intel_flags.add("Malware URL Match")
                intel_reasons.append(f"URLhaus reported {url} as malware distribution.")
            elif p.provider == "OpenPhish":
                intel_flags.add("Phishing URL Match")
                intel_reasons.append(f"OpenPhish reported {url} as a phishing site.")
            elif p.provider == "Google Safe Browsing":
                intel_flags.add("Safe Browsing Threat")
                intel_reasons.append(f"Google Safe Browsing reported {url} as {p.threat_type}.")
            elif p.provider == "VirusTotal":
                intel_flags.add("VirusTotal Threat")
                intel_reasons.append(f"VirusTotal reported {url} as malicious/suspicious.")

    intel_score = min(50, intel_score)
    
    # 3. Total Risk Calculation
    risk_score = min(100, url_score + intel_score)
    logger.info(f"[RISK FUSION] Final score: {risk_score}")
    
    # Flags & Explanations
    flags = list(url_analysis_result.signals)
    flags.extend(list(intel_flags))
    
    explanation = list(intel_reasons)
    if not explanation and flags:
        explanation.append("Structural anomalies detected in URL.")
    elif not explanation:
        explanation.append("No known threats or significant structural anomalies found.")
        
    # Overrides
    if intel_score > 0 and risk_score < 75:
        risk_score = 75
        
    # Classification Thresholds
    if risk_score <= 24:
        prediction = "SAFE"
        risk_level = "LOW"
    elif risk_score <= 49:
        prediction = "SUSPICIOUS"
        risk_level = "MEDIUM"
    elif risk_score <= 74:
        prediction = "SPAM"
        risk_level = "HIGH"
    else:
        prediction = "SCAM"
        risk_level = "CRITICAL"

    if prediction == "SCAM":
        confidence = min(1.0, 0.5 + (risk_score - 75) / 50.0)
    elif prediction == "SPAM":
        confidence = 0.5
    elif prediction == "SUSPICIOUS":
        confidence = 0.5 + (risk_score - 25) / 50.0
    else:
        confidence = 1.0 - (risk_score / 24.0)
        confidence = max(0.0, min(1.0, confidence))

    score_breakdown = {
        "url_structural_risk": url_score,
        "threat_intel_score": intel_score
    }
    
    iocs = {"urls": [url], "domains": [url_analysis_result.domain], "ips": [], "emails": []}
    if url_analysis_result.raw_ip:
        iocs["ips"].append(url_analysis_result.domain)
        
    return PredictionResult(
        prediction=prediction,
        confidence=round(confidence, 4),
        spam_probability=0.0,
        risk_score=risk_score,
        risk_level=risk_level,
        flags=flags,
        explanation=explanation,
        top_terms=[],
        score_breakdown=score_breakdown,
        iocs=iocs,
        url_analysis=[asdict(url_analysis_result)],
        threat_intelligence=threat_intelligence
    )
