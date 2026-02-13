from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import Optional
from pathlib import Path

class Settings(BaseSettings):
    """تنظیمات پیکربندی پروژه با پشتیبانی از .env"""
    
    # ========== Elasticsearch ==========
    ELASTIC_HOST: str = Field("http://host.docker.internal:9200", env="ELASTIC_HOST")
    ELASTIC_USER: str = Field("elastic", env="ELASTIC_USER")
    ELASTIC_PASSWORD: str = Field(..., env="ELASTIC_PASSWORD", min_length=1)
    ELASTIC_INDEX_PATTERN: str = Field(
        ".internal.alerts-security.alerts-default-*", 
        env="ELASTIC_INDEX_PATTERN"
    )
    TARGET_INDEX_PREFIX: str = Field("elastic-neo4j-attack-chain", env="TARGET_INDEX_PREFIX")
    
    # ========== Neo4j ==========
    NEO4J_URI: str = Field("bolt://host.docker.internal:7687", env="NEO4J_URI")
    NEO4J_USER: str = Field("neo4j", env="NEO4J_USER")
    NEO4J_PASSWORD: str = Field(..., env="NEO4J_PASSWORD", min_length=1)
    
    # ========== Query Parameters ==========
    TIME_RANGE_GTE: str = Field("now-24h", env="TIME_RANGE_GTE")
    TIME_RANGE_LTE: str = Field("now", env="TIME_RANGE_LTE")
    MIN_RISK_SCORE: int = Field(30, env="MIN_RISK_SCORE", ge=0, le=100)
    MAX_CHAINS: int = Field(50, env="MAX_CHAINS", ge=1, le=500)
    MAX_CHAIN_SIZE: int = Field(15, env="MAX_CHAIN_SIZE", ge=1, le=100)
    
    # ========== SEPSes Ontology Base URI ==========
    SEPSES_BASE_URI: str = Field(
        "https://w3id.org/sepses/vocab/event/log#", 
        env="SEPSES_BASE_URI"
    )
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @validator("ELASTIC_HOST", "NEO4J_URI")
    def validate_uri_scheme(cls, v):
        if not v.startswith(("http://", "https://", "bolt://")):
            raise ValueError(f"Invalid URI scheme: {v}")
        return v

    def get_target_index(self) -> str:
        """تولید نام اندیس هدف با تاریخ فعلی"""
        from datetime import datetime
        today = datetime.utcnow().strftime("%Y.%m.%d")
        return f"{self.TARGET_INDEX_PREFIX}-{today}"

# Singleton instance
settings = Settings()