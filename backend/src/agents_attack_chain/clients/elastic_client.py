import asyncio
import logging
from typing import Dict, Any, List
from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import ConnectionError, AuthenticationException, TransportError
from ..config.settings import settings

logger = logging.getLogger(__name__)

class ElasticSearchClient:
    """
    Async Elasticsearch client with SEPSes-compliant query execution
    NO curl/subprocess - pure async Python client
    """
    
    def __init__(self):
        self.client = AsyncElasticsearch(
            hosts=[settings.ELASTIC_HOST],
            basic_auth=(settings.ELASTIC_USER, settings.ELASTIC_PASSWORD),
            verify_certs=False,  # Disable for dev; enable in production with proper certs
            max_retries=3,
            retry_on_timeout=True,
            request_timeout=30
        )
        self._closed = False
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def close(self):
        if not self._closed:
            await self.client.close()
            self._closed = True
    
    async def fetch_attack_chains(
        self,
        time_gte: str = None,
        time_lte: str = None,
        min_risk_score: int = None,
        max_chains: int = None,
        max_chain_size: int = None
    ) -> Dict[str, Any]:
        """
        Execute optimized query for attack chain extraction with CORRECT syntax
        (Fixed all spacing errors from original JSON)
        """
        # Use defaults from settings if not provided
        time_gte = time_gte or settings.TIME_RANGE_GTE
        time_lte = time_lte or settings.TIME_RANGE_LTE
        min_risk_score = min_risk_score or settings.MIN_RISK_SCORE
        max_chains = max_chains or settings.MAX_CHAINS
        max_chain_size = max_chain_size or settings.MAX_CHAIN_SIZE
        
        query = {
            "size": 0,  # No top-level hits, only aggregations
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_gte,
                                    "lte": time_lte
                                }
                            }
                        },
                        {
                            "exists": {
                                "field": "kibana.alert.ancestors.id"
                            }
                        },
                        {
                            "terms": {
                                "kibana.alert.workflow_status": ["open", "acknowledged"]
                            }
                        },
                        {
                            "range": {
                                "kibana.alert.risk_score": {
                                    "gte": min_risk_score
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "attack_chains": {
                    "terms": {
                        "field": "kibana.alert.ancestors.id",
                        "size": max_chains,
                        "order": {"max_timestamp": "desc"}
                    },
                    "aggs": {
                        "max_timestamp": {
                            "max": {"field": "@timestamp"}
                        },
                        "alerts_in_chain": {
                            "top_hits": {
                                "size": max_chain_size,
                                "sort": [{"@timestamp": {"order": "asc"}}],  # Chronological order
                                "_source": {
                                    "includes": self._get_source_fields()
                                }
                            }
                        }
                    }
                }
            }
        }
        
        try:
            logger.info(f"Executing attack chain query: {time_gte} to {time_lte}")
            response = await self.client.search(
                index=settings.ELASTIC_INDEX_PATTERN,
                body=query
            )
            logger.info(f"Found {len(response['aggregations']['attack_chains']['buckets'])} attack chains")
            return response
        except (ConnectionError, AuthenticationException) as e:
            logger.error(f"Elasticsearch connection failed: {e}")
            raise
        except TransportError as e:
            logger.error(f"Elasticsearch query error: {e.info}")
            raise
    
    @staticmethod
    def _get_source_fields() -> List[str]:
        """Return exact fields required for SEPSes transformation"""
        return [
            "@timestamp",
            "source.ip", "source.port",
            "destination.ip", "destination.port",
            "host.name", "host.ip",
            "user.name",
            "process.pid", "process.name", "process.command_line",
            "file.path", "file.name",
            "kibana.alert.severity",
            "kibana.alert.risk_score",
            "kibana.alert.rule.name",
            "kibana.alert.rule.threat.*",  # MITRE TTPs
            "kibana.alert.ancestors",
            "kibana.alert.workflow_status",
            "kibana.alert.uuid"
        ]
    
    async def store_standardized_chain(self, chain: Dict[str, Any]) -> str:
        """Store standardized SEPSes chain in dedicated Elasticsearch index"""
        index_name = settings.get_target_index()
        result = await self.client.index(
            index=index_name,
            document=chain,
            refresh=True
        )
        logger.info(f"Stored chain in Elasticsearch: {index_name}/{result['_id']}")
        return result["_id"]