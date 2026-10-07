from abc import ABC, abstractmethod
from typing import List
from .models import ThreatIntelResult

class ThreatIntelProvider(ABC):
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass
        
    @abstractmethod
    async def check_url(self, url: str) -> ThreatIntelResult:
        pass
