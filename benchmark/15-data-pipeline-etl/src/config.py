"""
Data Pipeline ETL Agent Configuration

Configuration for an AI-powered ETL (Extract-Transform-Load) pipeline
that can query databases, transform data, and load results.

SECURITY MODEL:
This agent has access to:
- Multiple database connections
- File system for data export
- External APIs for enrichment
- Caching with pickle (dangerous!)

Production considerations:
- Use credential managers, not hardcoded secrets
- Implement query parameterization
- Sanitize data before loading
- Use secure serialization, not pickle
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional
import os


@dataclass
class DatabaseConfig:
    """Database connection configuration."""
    sqlite_path: Path = Path.home() / ".etl_agent" / "warehouse.db"
    postgres_host: str = os.getenv("POSTGRES_HOST", "localhost")
    postgres_port: int = int(os.getenv("POSTGRES_PORT", "5432"))
    postgres_user: str = os.getenv("POSTGRES_USER", "etl_agent")
    postgres_password: str = os.getenv("POSTGRES_PASSWORD", "")
    postgres_database: str = os.getenv("POSTGRES_DB", "analytics")
    max_query_rows: int = 10000
    query_timeout_seconds: int = 60


@dataclass
class StorageConfig:
    """File storage configuration."""
    data_dir: Path = Path.home() / ".etl_agent" / "data"
    export_dir: Path = Path.home() / ".etl_agent" / "exports"
    cache_dir: Path = Path.home() / ".etl_agent" / "cache"
    max_file_size_mb: int = 100
    allowed_formats: tuple = ("csv", "json", "parquet", "xlsx")


@dataclass
class APIConfig:
    """External API configuration for data enrichment."""
    enrichment_api_url: str = os.getenv("ENRICHMENT_API_URL", "https://api.example.com/enrich")
    enrichment_api_key: str = os.getenv("ENRICHMENT_API_KEY", "")
    geocoding_api_url: str = "https://nominatim.openstreetmap.org/search"
    http_timeout: int = 30
    max_retries: int = 3


@dataclass
class PipelineConfig:
    """Pipeline execution configuration."""
    max_parallel_tasks: int = 4
    checkpoint_enabled: bool = True
    checkpoint_interval: int = 1000  # rows
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600


db_config = DatabaseConfig()
storage_config = StorageConfig()
api_config = APIConfig()
pipeline_config = PipelineConfig()


def ensure_directories():
    """Create necessary directories."""
    for dir_path in [
        storage_config.data_dir,
        storage_config.export_dir,
        storage_config.cache_dir,
        db_config.sqlite_path.parent,
    ]:
        dir_path.mkdir(parents=True, exist_ok=True)
