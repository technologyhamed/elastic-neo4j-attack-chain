from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from .event import SEPSesLogEvent

@dataclass
class MITRETTP:
    """
    Represents MITRE ATT&CK technique referenced in kibana.alert.rule.threat
    Maps to custom extension (not native SEPSes, but compatible)
    """
    technique_id: str        # e.g., "T1059.001"
    technique_name: str      # e.g., "PowerShell"
    tactic: str              # e.g., "Execution"
    subtechnique: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "techniqueId": self.technique_id,
            "techniqueName": self.technique_name,
            "tactic": self.tactic,
            "subtechnique": self.subtechnique
        }

@dataclass
class AttackChain:
    """
    Represents a complete attack chain derived from Elastic ancestors aggregation
    NOT a native SEPSes class - a domain-specific wrapper for analysis
    """
    chain_id: str
    log_events: List[SEPSesLogEvent] = field(default_factory=list)
    size: int = 0
    first_timestamp: Optional[datetime] = None
    last_timestamp: Optional[datetime] = None
    unique_ttps: List[MITRETTP] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "chainId": self.chain_id,
            "size": self.size,
            "firstTimestamp": self.first_timestamp.isoformat() if self.first_timestamp else None,
            "lastTimestamp": self.last_timestamp.isoformat() if self.last_timestamp else None,
            "logEvents": [event.to_dict() for event in self.log_events],
            "uniqueTtps": [ttp.to_dict() for ttp in self.unique_ttps],
            "storedAt": datetime.utcnow().isoformat()
        }