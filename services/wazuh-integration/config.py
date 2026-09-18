from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    service_name: str = "wazuh-integration"
    service_version: str = "1.0.0"

    # Wazuh Manager Configuration
    wazuh_manager_url: str = "https://wazuh-manager:55000"
    wazuh_username: str = "wazuh-wui"
    wazuh_password: str
    wazuh_verify_ssl: bool = False

    # Wazuh Indexer Configuration
    wazuh_indexer_url: str = "https://wazuh-indexer:9200"
    indexer_username: str = "admin"
    indexer_password: str = "admin"
    indexer_verify_ssl: bool = False

    # Wazuh Alert Filtering
    min_severity: int = 7
    max_alerts_per_request: int = 100

    # AI Service Endpoints
    alert_triage_url: str = "http://alert-triage:8000"
    rag_service_url: str = "http://rag-service:8000"
    correlation_engine_url: str = "http://correlation-engine:8000"

    # RAG Enrichment Threshold
    rag_severity_threshold: int = 8

    # API Configuration
    host: str = "0.0.0.0"
    port: int = 8002
    log_level: str = "info"

    # Timeouts
    wazuh_api_timeout: int = 30
    ai_service_timeout: int = 60

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        fields = {
            "wazuh_password": {"env": "API_PASSWORD"}
        }


@lru_cache()
def get_settings() -> Settings:
    return Settings()