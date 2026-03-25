"""
Database operations for the Customer Operations Platform.

This module provides tools for interacting with the PostgreSQL database,
including customer queries, SQL execution, and data writes.
"""

from typing import Any, Dict, List, Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from langchain_core.tools import tool

from config import db_config
from tools.auth import require_permission, get_current_user, AuthorizationError


def get_db_connection():
    """
    Create a new database connection.

    Returns:
        psycopg2 connection object
    """
    return psycopg2.connect(
        host=db_config.host,
        port=db_config.port,
        database=db_config.database,
        user=db_config.user,
        password=db_config.password,
    )


@tool
def query_customer_db(customer_id: str, fields: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Query customer information from the database.

    Retrieves customer records by ID with optional field selection.
    This is a read-only operation that does not modify data.

    Args:
        customer_id: The unique identifier of the customer
        fields: Optional list of specific fields to retrieve

    Returns:
        Dictionary containing customer data

    Example:
        result = query_customer_db("cust_123", ["name", "email", "plan"])
    """
    if fields:
        columns = ", ".join(fields)
    else:
        columns = "*"

    query = f"SELECT {columns} FROM customers WHERE customer_id = %s"

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, (customer_id,))
            result = cursor.fetchone()
            return dict(result) if result else {}
    finally:
        conn.close()


@tool
def execute_sql_query(query: str, params: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
    """
    Execute an arbitrary SQL query with parameters.

    This function executes user-provided SQL queries against the database.
    It supports parameterized queries to prevent SQL injection, but the
    query structure itself is controlled by the caller.

    Args:
        query: The SQL query string to execute
        params: Optional list of parameters for the query

    Returns:
        List of dictionaries containing query results

    Warning:
        This tool allows arbitrary SQL execution. Ensure inputs are validated
        before use in production environments.

    Example:
        results = execute_sql_query(
            "SELECT * FROM orders WHERE status = %s AND created_at > %s",
            ["pending", "2024-01-01"]
        )
    """
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query, params or [])

            # Check if this is a SELECT query
            if cursor.description:
                results = cursor.fetchall()
                return [dict(row) for row in results]
            else:
                conn.commit()
                return [{"rows_affected": cursor.rowcount}]
    finally:
        conn.close()


@tool
def write_to_database(
    table: str,
    records: List[Dict[str, Any]],
    operation: str = "insert"
) -> Dict[str, Any]:
    """
    Write records to the database.

    Performs bulk insert or update operations on the specified table.
    This tool modifies database state and should be used with caution.

    Args:
        table: The target table name
        records: List of record dictionaries to write
        operation: Either "insert" or "upsert"

    Returns:
        Dictionary with operation results including rows affected

    Example:
        result = write_to_database(
            "customer_events",
            [{"customer_id": "123", "event": "login", "timestamp": "2024-01-15"}],
            operation="insert"
        )
    """
    if not records:
        return {"rows_affected": 0, "status": "no_records"}

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            columns = list(records[0].keys())
            placeholders = ", ".join(["%s"] * len(columns))
            column_names = ", ".join(columns)

            if operation == "insert":
                query = f"INSERT INTO {table} ({column_names}) VALUES ({placeholders})"
            elif operation == "upsert":
                update_clause = ", ".join([f"{col} = EXCLUDED.{col}" for col in columns])
                query = f"""
                    INSERT INTO {table} ({column_names}) VALUES ({placeholders})
                    ON CONFLICT (id) DO UPDATE SET {update_clause}
                """
            else:
                raise ValueError(f"Unknown operation: {operation}")

            rows_affected = 0
            for record in records:
                values = [record[col] for col in columns]
                cursor.execute(query, values)
                rows_affected += cursor.rowcount

            conn.commit()
            return {"rows_affected": rows_affected, "status": "success"}
    finally:
        conn.close()


@tool
@require_permission("admin")
def delete_customer_data(customer_id: str, hard_delete: bool = False) -> Dict[str, Any]:
    """
    Delete customer data from the database.

    This is a protected operation that requires admin permission.
    The authorization check ensures only admins can delete customer data.

    Args:
        customer_id: The customer ID to delete
        hard_delete: If True, permanently removes data. If False, soft delete.

    Returns:
        Dictionary with deletion results

    Raises:
        AuthorizationError: If user lacks admin permission
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if hard_delete:
                cursor.execute(
                    "DELETE FROM customers WHERE customer_id = %s",
                    (customer_id,)
                )
            else:
                cursor.execute(
                    "UPDATE customers SET deleted_at = NOW() WHERE customer_id = %s",
                    (customer_id,)
                )
            conn.commit()
            return {"customer_id": customer_id, "deleted": True, "hard": hard_delete}
    finally:
        conn.close()
