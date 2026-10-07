from typing import List, Optional

from pydantic import BaseModel, Field

from ml.inference import TermContribution

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_version: Optional[str] = None
    api_version: str

class RiskSignalOut(BaseModel):
    category: str
    label: str
    points: int
    matches: List[str]

class TermOut(BaseModel):
    term: str
    weight: float

class PredictRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000, description="The message text to analyze.")

class ScanUrlRequest(BaseModel):
    url: str = Field(..., description="The URL to scan.")

class PredictResponse(BaseModel):
    prediction: str = Field(..., description="SAFE, SUSPICIOUS, SPAM, or SCAM")
    confidence: float = Field(..., description="Confidence score 0.0 to 1.0")
    spam_probability: float = Field(..., description="Raw ML spam probability")
    risk_score: int = Field(..., description="Final combined risk score (0-100)")
    risk_level: str = Field(..., description="Risk severity level")
    flags: List[str] = Field(..., description="Threat indicators found")
    explanation: List[str] = Field(..., description="Human readable explanations")
    top_terms: Optional[List[TermContribution]] = None
    score_breakdown: dict = Field(..., description="Detailed score breakdown")
    model_version: Optional[str] = Field(None, description="The version of the ML model used")
    iocs: dict = Field(default_factory=lambda: {"urls": [], "domains": [], "ips": [], "emails": []})
    url_analysis: list = Field(default_factory=list)
    threat_intelligence: list = Field(default_factory=list)

class PageScanRequest(BaseModel):
    page_url: str
    links: list[str]

class PageScanSummary(BaseModel):
    clean: int
    suspicious: int
    threats: int

class NotableLink(BaseModel):
    url: str
    prediction: str
    risk_score: int
    reason: str

class PageScanResponse(BaseModel):
    scan_id: str
    page_url: str
    total_links_found: int
    links_analyzed: int
    external_links: int
    summary: PageScanSummary
    risk_score: int
    risk_level: str
    prediction: str
    notable_links: list[NotableLink]
