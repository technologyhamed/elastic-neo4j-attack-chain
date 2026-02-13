from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from .base import SEPSesEntity
from .resource import SEPSesHost, SEPSesProcess, SEPSesUser, SEPSesFile, SEPSesNetworkFlow
from .threat import MITRETTP

@dataclass
class SEPSesLogEvent(SEPSesEntity):
    """
    Maps to sepses:LogEvent (BASE CLASS in SEPSes ontology)
    Elastic Security Alerts are SPECIALIZED instances of LogEvent.
    
    IMPORTANT: There is NO "Alert" class in SEPSes ontology!
    Security alerts are modeled as LogEvents with additional properties:
      - sepses:hasSeverity (data property)
      - sepses:hasRiskScore (Elastic extension)
      - sepses:hasRuleName (Elastic extension)
      - sepses:hasWorkflowStatus (Elastic extension)
    
    Object Properties (relationships):
      - sepses:hasHost → SEPSesHost
      - sepses:hasProcess → SEPSesProcess
      - sepses:hasUser → SEPSesUser
      - sepses:hasFile → SEPSesFile
      - sepses:hasNetworkFlow → SEPSesNetworkFlow
    """
    timestamp: datetime
    severity: Optional[str] = None          # sepses:hasSeverity
    risk_score: Optional[int] = None        # Elastic extension
    rule_name: Optional[str] = None         # Elastic extension: rule.name
    workflow_status: Optional[str] = None   # Elastic: "open", "acknowledged"
    elastic_uuid: Optional[str] = None      # kibana.alert.uuid
    
    # Object Properties (SEPSes relationships)
    host: Optional[SEPSesHost] = None       # sepses:hasHost
    user: Optional[SEPSesUser] = None       # sepses:hasUser
    process: Optional[SEPSesProcess] = None # sepses:hasProcess
    file: Optional[SEPSesFile] = None       # sepses:hasFile
    network_flow: Optional[SEPSesNetworkFlow] = None  # sepses:hasNetworkFlow
    
    # Elastic-specific chain properties
    ancestors: List[str] = field(default_factory=list)  # kibana.alert.ancestors.id
    ttps: List[MITRETTP] = field(default_factory=list)  # MITRE techniques
    
    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "riskScore": self.risk_score,
            "ruleName": self.rule_name,
            "workflowStatus": self.workflow_status,
            "elasticUuid": self.elastic_uuid,
            "ancestors": self.ancestors,
        }
        if self.host: d["host"] = self.host.to_dict()
        if self.user: d["user"] = self.user.to_dict()
        if self.process: d["process"] = self.process.to_dict()
        if self.file: d["file"] = self.file.to_dict()
        if self.network_flow: d["networkFlow"] = self.network_flow.to_dict()
        if self.ttps: d["ttps"] = [ttp.to_dict() for ttp in self.ttps]
        return d