"""
Configuration module for the Customer Operations Platform.

This module centralizes all configuration values used across the platform,
including database connections, API endpoints, and service credentials.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class DatabaseConfig:
    """PostgreSQL database configuration."""

    host: str = os.getenv("POSTGRES_HOST", "localhost")
    port: int = int(os.getenv("POSTGRES_PORT", "5432"))
    database: str = os.getenv("POSTGRES_DB", "customer_ops")
    user: str = os.getenv("POSTGRES_USER", "app_user")
    password: str = os.getenv("POSTGRES_PASSWORD", "")

    @property
    def connection_string(self) -> str:
        """Generate PostgreSQL connection string."""
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass
class EmailConfig:
    """SMTP email configuration."""

    smtp_host: str = os.getenv("SMTP_HOST", "smtp.company.com")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    from_address: str = os.getenv("EMAIL_FROM", "support@company.com")
    use_tls: bool = os.getenv("SMTP_USE_TLS", "true").lower() == "true"


@dataclass
class TicketingConfig:
    """Support ticketing system API configuration."""

    base_url: str = os.getenv("TICKETING_API_URL", "https://tickets.company.com/api/v1")
    api_key: str = os.getenv("TICKETING_API_KEY", "")
    timeout: int = int(os.getenv("TICKETING_TIMEOUT", "30"))


@dataclass
class CRMConfig:
    """External CRM API configuration."""

    base_url: str = os.getenv("CRM_API_URL", "https://api.salesforce.com/v52.0")
    client_id: str = os.getenv("CRM_CLIENT_ID", "")
    client_secret: str = os.getenv("CRM_CLIENT_SECRET", "")
    access_token: Optional[str] = os.getenv("CRM_ACCESS_TOKEN")


@dataclass
class EnrichmentConfig:
    """Data enrichment API configuration."""

    base_url: str = os.getenv("ENRICHMENT_API_URL", "https://api.clearbit.com/v2")
    api_key: str = os.getenv("ENRICHMENT_API_KEY", "")


@dataclass
class FileConfig:
    """File system configuration."""

    documents_dir: str = os.getenv("DOCUMENTS_DIR", "/var/data/documents")
    csv_input_dir: str = os.getenv("CSV_INPUT_DIR", "/var/data/csv_input")
    temp_dir: str = os.getenv("TEMP_DIR", "/tmp/customer_ops")
    max_file_size_mb: int = int(os.getenv("MAX_FILE_SIZE_MB", "100"))


# Global configuration instances
db_config = DatabaseConfig()
email_config = EmailConfig()
ticketing_config = TicketingConfig()
crm_config = CRMConfig()
enrichment_config = EnrichmentConfig()
file_config = FileConfig()


# User roles for authorization
class UserRole:
    """User role constants."""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    DATA_ENGINEER = "data_engineer"


# Allowed operations per role
ROLE_PERMISSIONS = {
    UserRole.ADMIN: ["read", "write", "delete", "execute", "admin"],
    UserRole.OPERATOR: ["read", "write", "execute"],
    UserRole.DATA_ENGINEER: ["read", "write", "execute", "transform"],
    UserRole.VIEWER: ["read"],
}
