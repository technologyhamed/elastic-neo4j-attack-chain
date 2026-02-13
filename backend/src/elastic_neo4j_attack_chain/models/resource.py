from dataclasses import dataclass, field
from typing import List, Optional
from .base import SEPSesEntity

@dataclass
class SEPSesHost(SEPSesEntity):
    """
    Maps to sepses:Host in ontology
    Properties:
      - sepses:hasIP (data property)
      - sepses:hasHostname (data property)
    """
    hostname: Optional[str] = None
    ip: Optional[str] = None
    labels: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        d = super().to_dict()
        if self.hostname: d["hostname"] = self.hostname
        if self.ip: d["ip"] = self.ip
        if self.labels: d["labels"] = self.labels
        return d

@dataclass
class SEPSesProcess(SEPSesEntity):
    """
    Maps to sepses:Process in ontology
    Properties:
      - sepses:hasPID (data property)
      - sepses:hasName (data property)
      - sepses:hasCommandLine (data property)
    """
    pid: Optional[int] = None
    name: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    
    def to_dict(self) -> dict:
        d = super().to_dict()
        if self.pid: d["pid"] = self.pid
        if self.name: d["name"] = self.name
        if self.command_line: d["commandLine"] = self.command_line
        if self.parent_pid: d["parentPid"] = self.parent_pid
        return d

@dataclass
class SEPSesUser(SEPSesEntity):
    """
    Maps to sepses:User in ontology
    Properties:
      - sepses:hasUsername (data property)
      - sepses:hasDomain (data property)
    """
    username: Optional[str] = None
    domain: Optional[str] = None
    
    def to_dict(self) -> dict:
        d = super().to_dict()
        if self.username: d["username"] = self.username
        if self.domain: d["domain"] = self.domain
        return d

@dataclass
class SEPSesFile(SEPSesEntity):
    """
    Maps to sepses:File in ontology
    Properties:
      - sepses:hasPath (data property)
      - sepses:hasName (data property)
      - sepses:hasHash (data property)
    """
    path: Optional[str] = None
    name: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    
    def to_dict(self) -> dict:
        d = super().to_dict()
        if self.path: d["path"] = self.path
        if self.name: d["name"] = self.name
        if self.hash_md5: d["hashMd5"] = self.hash_md5
        if self.hash_sha256: d["hashSha256"] = self.hash_sha256
        return d

@dataclass
class SEPSesNetworkFlow(SEPSesEntity):
    """
    Maps to sepses:NetworkFlow in ontology
    Properties:
      - sepses:hasSrcIP (data property)
      - sepses:hasSrcPort (data property)
      - sepses:hasDstIP (data property)
      - sepses:hasDstPort (data property)
      - sepses:hasProtocol (data property)
    """
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    
    def to_dict(self) -> dict:
        d = super().to_dict()
        if self.src_ip: d["srcIp"] = self.src_ip
        if self.src_port: d["srcPort"] = self.src_port
        if self.dst_ip: d["dstIp"] = self.dst_ip
        if self.dst_port: d["dstPort"] = self.dst_port
        if self.protocol: d["protocol"] = self.protocol
        return d