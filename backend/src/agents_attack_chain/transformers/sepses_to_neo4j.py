from typing import List
from ..models.threat import AttackChain
from ..models.event import SEPSesLogEvent
from ..models.resource import (
    SEPSesHost, SEPSesProcess, SEPSesUser, 
    SEPSesFile, SEPSesNetworkFlow
)
from ..models.threat import MITRETTP

class SEPSesToNeo4jTransformer:
    """
    Generates Cypher queries to store SEPSes ontology entities in Neo4j
    Uses proper SEPSes relationship names (hasHost, hasProcess, etc.)
    """
    
    @staticmethod
    def generate_chain_queries(chain: AttackChain) -> List[str]:
        """Generate all Cypher queries needed to store a complete attack chain"""
        queries = []
        
        # 1. Create unique resource entities (idempotent with MERGE)
        queries.extend(SEPSesToNeo4jTransformer._create_resource_queries(chain))
        
        # 2. Create LogEvent nodes and their relationships
        queries.extend(SEPSesToNeo4jTransformer._create_logevent_queries(chain))
        
        # 3. Create temporal relationships between LogEvents (PRECEDES)
        queries.extend(SEPSesToNeo4jTransformer._create_temporal_queries(chain))
        
        # 4. Create AttackChain metadata node and relationships
        queries.extend(SEPSesToNeo4jTransformer._create_chain_metadata_queries(chain))
        
        return queries
    
    @staticmethod
    def _create_resource_queries(chain: AttackChain) -> List[str]:
        """Generate MERGE queries for all unique resources in the chain"""
        queries = set()
        seen_hosts = set()
        seen_processes = set()
        seen_users = set()
        seen_files = set()
        seen_flows = set()
        
        for event in chain.log_events:
            # Host
            if event.host and event.host.id not in seen_hosts:
                seen_hosts.add(event.host.id)
                props = []
                if event.host.hostname: props.append(f"hostname: '{event.host.hostname}'")
                if event.host.ip: props.append(f"ip: '{event.host.ip}'")
                props_str = ", ".join(props)
                queries.add(f"MERGE (h:Host {{id: '{event.host.id}'}}) SET h:SEPSesResource, h += {{{props_str}}}")
            
            # Process
            if event.process and event.process.id not in seen_processes:
                seen_processes.add(event.process.id)
                props = []
                if event.process.pid: props.append(f"pid: {event.process.pid}")
                if event.process.name: props.append(f"name: '{event.process.name}'")
                if event.process.command_line: props.append(f"commandLine: '{event.process.command_line}'")
                props_str = ", ".join(props)
                queries.add(f"MERGE (p:Process {{id: '{event.process.id}'}}) SET p:SEPSesResource, p += {{{props_str}}}")
            
            # User
            if event.user and event.user.id not in seen_users:
                seen_users.add(event.user.id)
                if event.user.username:
                    queries.add(f"MERGE (u:User {{id: '{event.user.id}'}}) SET u:SEPSesResource, u.username = '{event.user.username}'")
            
            # File
            if event.file and event.file.id not in seen_files:
                seen_files.add(event.file.id)
                props = []
                if event.file.path: props.append(f"path: '{event.file.path}'")
                if event.file.name: props.append(f"name: '{event.file.name}'")
                props_str = ", ".join(props)
                queries.add(f"MERGE (f:File {{id: '{event.file.id}'}}) SET f:SEPSesResource, f += {{{props_str}}}")
            
            # NetworkFlow
            if event.network_flow and event.network_flow.id not in seen_flows:
                seen_flows.add(event.network_flow.id)
                props = []
                if event.network_flow.src_ip: props.append(f"srcIp: '{event.network_flow.src_ip}'")
                if event.network_flow.src_port: props.append(f"srcPort: {event.network_flow.src_port}")
                if event.network_flow.dst_ip: props.append(f"dstIp: '{event.network_flow.dst_ip}'")
                if event.network_flow.dst_port: props.append(f"dstPort: {event.network_flow.dst_port}")
                props_str = ", ".join(props)
                queries.add(f"MERGE (n:NetworkFlow {{id: '{event.network_flow.id}'}}) SET n:SEPSesResource, n += {{{props_str}}}")
        
        return list(queries)
    
    @staticmethod
    def _create_logevent_queries(chain: AttackChain) -> List[str]:
        """Generate CREATE queries for LogEvent nodes with relationships"""
        queries = []
        
        for event in chain.log_events:
            # Build LogEvent properties
            props = [
                f"id: '{event.id}'",
                f"timestamp: datetime('{event.timestamp.isoformat()}')",
                f"severity: '{event.severity}'" if event.severity else None,
                f"riskScore: {event.risk_score}" if event.risk_score else None,
                f"ruleName: '{event.rule_name}'" if event.rule_name else None,
                f"workflowStatus: '{event.workflow_status}'" if event.workflow_status else None,
                f"elasticUuid: '{event.elastic_uuid}'" if event.elastic_uuid else None
            ]
            props = [p for p in props if p]
            props_str = ", ".join(props)
            
            # Create LogEvent node
            queries.append(f"CREATE (e:LogEvent {{ {props_str} }}) SET e:SEPSesLogEvent")
            
            # Create relationships to resources
            rels = []
            if event.host:
                rels.append(f"(e)-[:HAS_HOST]->(:Host {{id: '{event.host.id}'}})")
            if event.process:
                rels.append(f"(e)-[:HAS_PROCESS]->(:Process {{id: '{event.process.id}'}})")
            if event.user:
                rels.append(f"(e)-[:HAS_USER]->(:User {{id: '{event.user.id}'}})")
            if event.file:
                rels.append(f"(e)-[:HAS_FILE]->(:File {{id: '{event.file.id}'}})")
            if event.network_flow:
                rels.append(f"(e)-[:HAS_NETWORK_FLOW]->(:NetworkFlow {{id: '{event.network_flow.id}'}})")
            
            for rel in rels:
                queries.append(f"MATCH {rel}")
            
            # Create relationships to MITRE techniques
            for ttp in event.ttps:
                queries.append(
                    f"MERGE (t:Technique {{id: '{ttp.technique_id}'}}) "
                    f"SET t.name = '{ttp.technique_name}', t.tactic = '{ttp.tactic}' "
                    f"WITH t MATCH (e:LogEvent {{id: '{event.id}'}}) "
                    f"MERGE (e)-[:USES_TTP]->(t)"
                )
        
        return queries
    
    @staticmethod
    def _create_temporal_queries(chain: AttackChain) -> List[str]:
        """Create PRECEDES relationships between consecutive LogEvents"""
        queries = []
        events_sorted = sorted(chain.log_events, key=lambda e: e.timestamp)
        
        for i in range(len(events_sorted) - 1):
            prev_id = events_sorted[i].id
            curr_id = events_sorted[i+1].id
            queries.append(
                f"MATCH (prev:LogEvent {{id: '{prev_id}'}}), (curr:LogEvent {{id: '{curr_id}'}}) "
                f"MERGE (prev)-[:PRECEDES {{chainId: '{chain.chain_id}', step: {i}}}]->(curr)"
            )
        
        return queries
    
    @staticmethod
    def _create_chain_metadata_queries(chain: AttackChain) -> List[str]:
        """Create AttackChain metadata node with relationships to all events"""
        queries = [
            f"MERGE (c:AttackChain {{id: '{chain.chain_id}'}}) "
            f"SET c.size = {chain.size}, "
            f"c.firstTimestamp = datetime('{chain.first_timestamp.isoformat()}'), "
            f"c.lastTimestamp = datetime('{chain.last_timestamp.isoformat()}'), "
            f"c.storedAt = datetime()"
        ]
        
        # Link all events to chain
        for event in chain.log_events:
            queries.append(
                f"MATCH (c:AttackChain {{id: '{chain.chain_id}'}}), "
                f"(e:LogEvent {{id: '{event.id}'}}) "
                f"MERGE (c)-[:CONTAINS_EVENT]->(e)"
            )
        
        # Link unique TTPs to chain
        for ttp in chain.unique_ttps:
            queries.append(
                f"MATCH (c:AttackChain {{id: '{chain.chain_id}'}}), "
                f"(t:Technique {{id: '{ttp.technique_id}'}}) "
                f"MERGE (c)-[:USES_TTP]->(t)"
            )
        
        return queries