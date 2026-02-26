"""
Database Schema Management for Neo4j based on SEPSes Ontology
Defines indexes and constraints aligned with attack chain data model
"""

from typing import List, Tuple, Dict
import logging

logger = logging.getLogger(__name__)

class Neo4jSchemaManager:
    """
    Manages Neo4j database schema (indexes and constraints) for SEPSes-compliant attack chains.
    Schema design based on:
    - SEPSes Ontology classes: LogEvent, Host, Process, User, File, NetworkFlow
    - Elastic Security alert structure (Final-Kill-chain.json fields)
    - Attack chain analysis requirements
    """
    
    # Indexes for query performance optimization
    INDEXES: List[Tuple[str, str, str]] = [
        # (label, property, index_name)
        ("LogEvent", "id", "idx_logevent_id"),
        ("LogEvent", "timestamp", "idx_logevent_timestamp"),
        ("LogEvent", "elasticUuid", "idx_logevent_uuid"),
        ("LogEvent", "severity", "idx_logevent_severity"),
        ("LogEvent", "riskScore", "idx_logevent_riskscore"),
        ("LogEvent", "ruleName", "idx_logevent_rulename"),
        ("Host", "id", "idx_host_id"),
        ("Host", "hostname", "idx_host_hostname"),
        ("Host", "ip", "idx_host_ip"),
        ("Process", "id", "idx_process_id"),
        ("Process", "pid", "idx_process_pid"),
        ("Process", "name", "idx_process_name"),
        ("User", "id", "idx_user_id"),
        ("User", "username", "idx_user_username"),
        ("File", "id", "idx_file_id"),
        ("File", "path", "idx_file_path"),
        ("File", "name", "idx_file_name"),
        ("NetworkFlow", "id", "idx_networkflow_id"),
        ("NetworkFlow", "srcIp", "idx_networkflow_srcip"),
        ("NetworkFlow", "dstIp", "idx_networkflow_dstip"),
        ("AttackChain", "id", "idx_attackchain_id"),
        ("AttackChain", "size", "idx_attackchain_size"),
        ("AttackChain", "firstTimestamp", "idx_attackchain_firstts"),
        ("AttackChain", "lastTimestamp", "idx_attackchain_lastts"),
        ("Technique", "id", "idx_technique_id"),
        ("Technique", "tactic", "idx_technique_tactic"),
        ("Technique", "techniqueName", "idx_technique_name"),
    ]
    
    # Constraints for data integrity (uniqueness)
    CONSTRAINTS: List[Tuple[str, str, str]] = [
        # (label, property, constraint_name)
        ("LogEvent", "id", "constraint_logevent_id_unique"),
        ("Host", "id", "constraint_host_id_unique"),
        ("Process", "id", "constraint_process_id_unique"),
        ("User", "id", "constraint_user_id_unique"),
        ("File", "id", "constraint_file_id_unique"),
        ("NetworkFlow", "id", "constraint_networkflow_id_unique"),
        ("AttackChain", "id", "constraint_attackchain_id_unique"),
        ("Technique", "id", "constraint_technique_id_unique"),
    ]
    
    @staticmethod
    def get_create_index_queries() -> List[str]:
        """Generate Cypher queries to create all indexes (idempotent with IF NOT EXISTS)"""
        queries = []
        for label, prop, name in Neo4jSchemaManager.INDEXES:
            queries.append(
                f"CREATE INDEX {name} IF NOT EXISTS "
                f"FOR (n:{label}) ON (n.`{prop}`)"
            )
        return queries
    
    @staticmethod
    def get_create_constraint_queries() -> List[str]:
        """Generate Cypher queries to create all uniqueness constraints"""
        queries = []
        for label, prop, name in Neo4jSchemaManager.CONSTRAINTS:
            queries.append(
                f"CREATE CONSTRAINT {name} IF NOT EXISTS "
                f"FOR (n:{label}) REQUIRE n.`{prop}` IS UNIQUE"
            )
        return queries
    
    @staticmethod
    def get_schema_info_query() -> str:
        """Query to show current schema status"""
        return """
        CALL db.indexes() YIELD name, labelsOrTypes, properties, type, state
        WHERE state = 'ONLINE'
        RETURN 'Index' AS type, name, labelsOrTypes[0] AS label, properties[0] AS property, type AS indexType
        UNION ALL
        CALL db.constraints() YIELD name, description, entityType, properties
        WHERE entityType = 'NODE'
        RETURN 'Constraint' AS type, name, labelsOrTypes[0] AS label, properties[0] AS property, description
        ORDER BY type DESC, label, property
        """
    
    @staticmethod
    async def initialize_schema(neo4j_client) -> Dict[str, int]:
        """
        Initialize Neo4j schema with all required indexes and constraints.
        Idempotent operation - safe to run multiple times.
        
        Returns:
            Dict with counts: {"indexes_created": int, "constraints_created": int}
        """
        logger.info("🔧 Initializing Neo4j schema for SEPSes attack chain model...")
        
        indexes_created = 0
        constraints_created = 0
        
        # Create indexes
        for query in Neo4jSchemaManager.get_create_index_queries():
            try:
                await neo4j_client.execute_write(query)
                indexes_created += 1
                logger.debug(f"✓ Index created/verified: {query.split()[2]}")
            except Exception as e:
                # Ignore duplicate index errors (Neo4j 5.x returns error even with IF NOT EXISTS in some cases)
                if "already exists" not in str(e).lower() and "equivalent" not in str(e).lower():
                    logger.warning(f"⚠️ Index creation warning: {str(e)[:100]}")
        
        logger.info(f"✅ Created/verified {indexes_created} indexes")
        
        # Create constraints
        for query in Neo4jSchemaManager.get_create_constraint_queries():
            try:
                await neo4j_client.execute_write(query)
                constraints_created += 1
                logger.debug(f"✓ Constraint created/verified: {query.split()[2]}")
            except Exception as e:
                # Ignore duplicate constraint errors
                if "already exists" not in str(e).lower() and "equivalent" not in str(e).lower():
                    logger.warning(f"⚠️ Constraint creation warning: {str(e)[:100]}")
        
        logger.info(f"✅ Created/verified {constraints_created} constraints")
        logger.info("✨ Neo4j schema initialization complete")
        
        return {
            "indexes_created": indexes_created,
            "constraints_created": constraints_created
        }
    
    @staticmethod
    async def check_schema_status(neo4j_client) -> Dict:
        """Check current schema status and return statistics"""
        try:
            query = Neo4jSchemaManager.get_schema_info_query()
            result = await neo4j_client.execute_read(query)
            
            indexes = [r for r in result if r["type"] == "Index"]
            constraints = [r for r in result if r["type"] == "Constraint"]
            
            return {
                "status": "healthy",
                "total_indexes": len(indexes),
                "total_constraints": len(constraints),
                "indexes": indexes,
                "constraints": constraints,
                "expected_indexes": len(Neo4jSchemaManager.INDEXES),
                "expected_constraints": len(Neo4jSchemaManager.CONSTRAINTS)
            }
        except Exception as e:
            logger.error(f"Schema status check failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "expected_indexes": len(Neo4jSchemaManager.INDEXES),
                "expected_constraints": len(Neo4jSchemaManager.CONSTRAINTS)
            }