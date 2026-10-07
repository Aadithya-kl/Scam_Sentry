from enum import Enum
from pydantic import BaseModel
from typing import List, Optional

class ProviderStatus(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    NOT_ENABLED = "NOT_ENABLED"
    CHECKED = "CHECKED"
    NO_MATCH = "NO_MATCH"
    MATCH = "MATCH"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    SKIPPED_FOR_PRIVACY = "SKIPPED_FOR_PRIVACY"
    UNAVAILABLE = "UNAVAILABLE"

class ThreatIntelResult(BaseModel):
    provider: str
    status: ProviderStatus
    found: bool = False
    threat_type: Optional[str] = None
    confidence: Optional[str] = None
    details: Optional[str] = None
    indicator: Optional[str] = None
    indicator_type: Optional[str] = None
    malicious_votes: Optional[int] = None
    suspicious_votes: Optional[int] = None
    harmless_votes: Optional[int] = None
