"""
Tools package for the Customer Operations Platform.

This package contains all tool implementations used by the AI agents
for customer operations and data pipeline tasks.
"""

from tools.auth import (
    check_permission,
    get_current_user,
    require_permission,
    AuthorizationError,
)
from tools.database import (
    query_customer_db,
    execute_sql_query,
    write_to_database,
)
from tools.email import send_customer_email
from tools.tickets import create_support_ticket, update_support_ticket
from tools.files import (
    read_customer_document,
    write_customer_document,
    read_csv_file,
)
from tools.crm import sync_to_crm
from tools.shell import run_transformation_command, cleanup_temp_files

__all__ = [
    # Auth
    "check_permission",
    "get_current_user",
    "require_permission",
    "AuthorizationError",
    # Database
    "query_customer_db",
    "execute_sql_query",
    "write_to_database",
    # Email
    "send_customer_email",
    # Tickets
    "create_support_ticket",
    "update_support_ticket",
    # Files
    "read_customer_document",
    "write_customer_document",
    "read_csv_file",
    # CRM
    "sync_to_crm",
    # Shell
    "run_transformation_command",
    "cleanup_temp_files",
]
