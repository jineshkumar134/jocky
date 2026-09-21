"""
JOCKY Configuration Settings
"""
from functools import lru_cache
from typing import Any
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "JOCKY Forensic Framework"
    VERSION: str = "0.1.0"
    PHASE: str = "Phase 0 - Foundation Setup"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    
    # Optional Database & Storage settings
    MONGODB_URI: str = "mongodb://localhost:27017/jocky_forensics"
    DATABASE_FALLBACK_LOCAL: bool = True
    
    # Blockchain & Anchoring defaults
    EVM_RPC_URL: str = "https://eth-sepolia.public.blastapi.io"
    EVM_CHAIN_ID: int = 11155111
    IPFS_GATEWAY_URL: str = "https://ipfs.io/ipfs/"
    IPFS_API_URL: str = "http://127.0.0.1:5001"
    EVM_ANCHOR_CONTRACT_ADDRESS: str = "0x0000000000000000000000000000000000000000"
    
    # Lab & Simulation Settings
    SECURITY_LAB_MODE: str = "simulation"
    ALLOW_REMOTE_EXECUTION: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("EVM_CHAIN_ID", mode="before")
    @classmethod
    def parse_chain_id(cls, v: Any) -> int:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return 11155111
            try:
                return int(v)
            except ValueError:
                return 11155111
        return int(v) if v is not None else 11155111

    @field_validator("API_PORT", mode="before")
    @classmethod
    def parse_port(cls, v: Any) -> int:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return 8000
            try:
                return int(v)
            except ValueError:
                return 8000
        return int(v) if v is not None else 8000


@lru_cache
def get_settings() -> Settings:
    try:
        return Settings()
    except Exception:
        return Settings(_env_file=None)
