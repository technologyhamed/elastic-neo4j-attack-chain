import asyncio
import logging
from typing import List
from ..clients.elastic_client import ElasticSearchClient
from ..clients.neo4j_client import Neo4jClient
from ..transformers.elastic_to_sepses import ElasticToSEPSesTransformer
from ..transformers.sepses_to_neo4j import SEPSesToNeo4jTransformer
from ..models.threat import AttackChain
from ..db.schema import Neo4jSchemaManager  # <-- افزودن ایمپورت جدید

logger = logging.getLogger(__name__)

class AsyncDataManager:
    """
    Unified async data manager for the entire pipeline:
    1. Fetch from Elasticsearch
    2. Transform to SEPSes ontology
    3. Store standardized in Elasticsearch
    4. Store graph in Neo4j
    """
    
    def __init__(self):
        self.es_client = ElasticSearchClient()
        self.neo4j_client = Neo4jClient()
        self.sepses_transformer = ElasticToSEPSesTransformer()
        self.neo4j_transformer = SEPSesToNeo4jTransformer()
        self.schema_initialized = False  # <-- فلگ جدید برای جلوگیری از ایجاد مکرر
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def close(self):
        await self.es_client.close()
        await self.neo4j_client.close()
    
    async def initialize_schema(self) -> None:
        """
        Initialize Neo4j schema (indexes + constraints) if not already initialized.
        Called automatically during process_attack_chains().
        """
        if self.schema_initialized:
            logger.debug("Neo4j schema already initialized - skipping")
            return
        
        logger.info("🔍 Checking/initializing Neo4j schema...")
        status = await Neo4jSchemaManager.check_schema_status(self.neo4j_client)
        
        # Initialize schema if missing expected objects
        if (status.get("status") == "error" or 
            status.get("total_indexes", 0) < status.get("expected_indexes", 10) or
            status.get("total_constraints", 0) < status.get("expected_constraints", 5)):
            logger.warning("⚠️ Schema incomplete - initializing now...")
            await Neo4jSchemaManager.initialize_schema(self.neo4j_client)
        else:
            logger.info(f"✅ Neo4j schema verified ({status['total_indexes']} indexes, {status['total_constraints']} constraints)")
        
        self.schema_initialized = True
    
    async def process_attack_chains(self) -> List[str]:
        """
        End-to-end processing pipeline:
        Elasticsearch → SEPSes transformation → Standardized storage → Neo4j graph
        
        Schema initialization is performed automatically before data storage.
        """
        logger.info("🚀 Starting attack chain processing pipeline...")
        
        # Step 0: Ensure Neo4j schema is initialized (critical for data integrity)
        await self.initialize_schema()
        
        # Step 1: Fetch raw chains from Elasticsearch
        response = await self.es_client.fetch_attack_chains()
        buckets = response["aggregations"]["attack_chains"]["buckets"]
        logger.info(f"📥 Fetched {len(buckets)} raw attack chains from Elasticsearch")
        
        if not buckets:
            logger.warning("⚠️ No attack chains found in the specified time range")
            return []
        
        # Step 2: Transform to SEPSes ontology
        chains: List[AttackChain] = []
        for bucket in buckets:
            try:
                chain = self.sepses_transformer.transform_attack_chain(bucket)
                if chain.log_events:  # Only keep chains with events
                    chains.append(chain)
                    logger.debug(f"🔄 Transformed chain {chain.chain_id} with {chain.size} events")
            except Exception as e:
                logger.error(f"❌ Error transforming chain: {e}")
                continue
        
        logger.info(f"✅ Transformed {len(chains)} chains to SEPSes ontology")
        
        if not chains:
            logger.warning("⚠️ No valid chains after transformation")
            return []
        
        # Step 3: Store standardized chains in Elasticsearch
        stored_ids = []
        for chain in chains:
            chain_dict = chain.to_dict()
            stored_id = await self.es_client.store_standardized_chain(chain_dict)
            stored_ids.append(stored_id)
        
        logger.info(f"💾 Stored {len(stored_ids)} standardized chains in Elasticsearch index: {self.es_client._get_target_index()}")
        
        # Step 4: Store in Neo4j graph database (with schema already initialized)
        neo4j_count = await self._store_in_neo4j(chains)
        logger.info(f"🔗 Stored {neo4j_count} chains in Neo4j graph database")
        
        return stored_ids
    
    async def _store_in_neo4j(self, chains: List[AttackChain]) -> int:
        """Store all chains in Neo4j with proper SEPSes relationships"""
        stored_count = 0
        for chain in chains:
            queries = self.neo4j_transformer.generate_chain_queries(chain)
            for query in queries:
                try:
                    await self.neo4j_client.execute_write(query)
                except Exception as e:
                    # Handle duplicate node errors gracefully (due to constraints)
                    if "already exists" in str(e).lower() or "ConstraintValidationFailed" in str(e):
                        logger.debug(f"ℹ️ Skipping duplicate node/relationship: {str(e)[:80]}")
                        continue
                    logger.error(f"❌ Neo4j query failed: {e}\nQuery preview: {query[:150]}...")
                    continue
            stored_count += 1
        
        return stored_count
    
    async def get_sample_attack_chain(self) -> dict:
        """Fetch a sample attack chain from Neo4j for visualization"""
        query = """
        MATCH (c:AttackChain)
        WHERE c.size >= 3
        WITH c
        ORDER BY c.lastTimestamp DESC
        LIMIT 1
        MATCH (c)-[:CONTAINS_EVENT]->(e:LogEvent)
        OPTIONAL MATCH (e)-[:HAS_HOST]->(h:Host)
        OPTIONAL MATCH (e)-[:HAS_PROCESS]->(p:Process)
        OPTIONAL MATCH (e)-[:USES_TTP]->(t:Technique)
        RETURN c.chain_id AS chainId, 
               c.size AS size,
               c.firstTimestamp AS firstTimestamp,
               c.lastTimestamp AS lastTimestamp,
               collect({
                 timestamp: toString(e.timestamp),
                 ruleName: e.ruleName,
                 severity: e.severity,
                 riskScore: e.riskScore,
                 hostname: h.hostname,
                 processName: p.name,
                 technique: t.techniqueName,
                 tactic: t.tactic
               }) AS events
        """
        result = await self.neo4j_client.execute_read(query)
        return result[0] if result else {}
    
    async def get_schema_status(self) -> dict:
        """Public method to check Neo4j schema status"""
        return await Neo4jSchemaManager.check_schema_status(self.neo4j_client)