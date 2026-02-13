from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

@dataclass
class SEPSesEntity:
    """
    Base class for all SEPSes ontology entities.
    Maps to owl:Thing in the ontology.
    """
    id: str  # Full URI: https://w3id.org/sepses/vocab/event/log#ClassName/identifier
    timestamp: Optional[datetime] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        result = {"id": self.id}
        if self.timestamp:
            result["timestamp"] = self.timestamp.isoformat()
        return result