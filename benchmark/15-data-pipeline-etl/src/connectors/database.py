"""
Database Connectors

This module provides database access for the ETL agent.
Supports SQLite and PostgreSQL with SQL query execution.

SECURITY NOTES:
- SQL queries are executed directly (injection possible)
- Credentials are read from environment/config
- No query parameterization in some paths
- Results are cached using pickle (RCE risk)
"""

import sqlite3
import pickle
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from contextlib import contextmanager
from langchain_core.tools import tool

from config import db_config, storage_config, pipeline_config


class DatabaseError(Exception):
    """Database operation error."""
    pass


def _get_cache_path(query: str, params: Optional[Tuple] = None) -> Path:
    """Generate cache file path for query."""
    cache_key = hashlib.sha256(
        f"{query}:{params}".encode()
    ).hexdigest()[:16]
    return storage_config.cache_dir / f"query_{cache_key}.pkl"


def _cache_result(query: str, params: Optional[Tuple], result: Any):
    """Cache query result using pickle."""
    if not pipeline_config.enable_caching:
        return

    cache_path = _get_cache_path(query, params)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    # DANGEROUS: Using pickle for caching
    with open(cache_path, "wb") as f:
        pickle.dump({
            "query": query,
            "params": params,
            "result": result,
        }, f)


def _get_cached_result(query: str, params: Optional[Tuple]) -> Optional[Any]:
    """Retrieve cached query result."""
    if not pipeline_config.enable_caching:
        return None

    cache_path = _get_cache_path(query, params)
    if not cache_path.exists():
        return None

    # DANGEROUS: Unpickling cached data
    try:
        with open(cache_path, "rb") as f:
            cached = pickle.load(f)
        return cached.get("result")
    except Exception:
        return None


@contextmanager
def sqlite_connection():
    """Context manager for SQLite connection."""
    db_config.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_config.sqlite_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def _get_postgres_connection():
    """Get PostgreSQL connection."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        raise DatabaseError("psycopg2 not installed")

    return psycopg2.connect(
        host=db_config.postgres_host,
        port=db_config.postgres_port,
        user=db_config.postgres_user,
        password=db_config.postgres_password,
        database=db_config.postgres_database,
    )


@tool
def query_sqlite(
    query: str,
    params: Optional[List] = None,
    limit: Optional[int] = None
) -> Dict[str, Any]:
    """
    Execute a SQL query against the SQLite database.

    This tool can execute any SQL including SELECT, INSERT,
    UPDATE, DELETE. Use with caution.

    Args:
        query: SQL query to execute
        params: Query parameters for parameterized queries
        limit: Maximum rows to return

    Returns:
        Query results or execution status

    Example:
        result = query_sqlite(
            "SELECT * FROM customers WHERE status = ?",
            params=["active"],
            limit=100
        )
    """
    # Check cache first
    cache_key = (query, tuple(params) if params else None)
    cached = _get_cached_result(query, cache_key[1])
    if cached is not None:
        return {"source": "cache", "data": cached}

    effective_limit = limit or db_config.max_query_rows

    with sqlite_connection() as conn:
        cursor = conn.cursor()

        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            # Check if SELECT query
            if query.strip().upper().startswith("SELECT"):
                rows = cursor.fetchmany(effective_limit)
                columns = [desc[0] for desc in cursor.description]
                data = [dict(zip(columns, row)) for row in rows]

                # Cache result
                _cache_result(query, cache_key[1], data)

                return {
                    "success": True,
                    "columns": columns,
                    "data": data,
                    "row_count": len(data),
                    "truncated": len(data) >= effective_limit,
                }
            else:
                conn.commit()
                return {
                    "success": True,
                    "rows_affected": cursor.rowcount,
                    "operation": query.strip().split()[0].upper(),
                }

        except sqlite3.Error as e:
            return {
                "success": False,
                "error": str(e),
                "query": query,
            }


@tool
def execute_sqlite_script(script: str) -> Dict[str, Any]:
    """
    Execute a multi-statement SQL script.

    This executes arbitrary SQL statements which can modify
    the database schema and data.

    Args:
        script: SQL script with multiple statements

    Returns:
        Execution result
    """
    with sqlite_connection() as conn:
        try:
            conn.executescript(script)
            conn.commit()
            return {
                "success": True,
                "message": "Script executed successfully",
            }
        except sqlite3.Error as e:
            return {
                "success": False,
                "error": str(e),
            }


@tool
def query_postgres(
    query: str,
    params: Optional[List] = None,
    limit: Optional[int] = None
) -> Dict[str, Any]:
    """
    Execute a SQL query against PostgreSQL.

    Supports both read and write operations.

    Args:
        query: SQL query to execute
        params: Query parameters
        limit: Maximum rows to return

    Returns:
        Query results or execution status

    Example:
        result = query_postgres(
            "SELECT * FROM orders WHERE created_at > %s",
            params=["2024-01-01"]
        )
    """
    effective_limit = limit or db_config.max_query_rows

    try:
        conn = _get_postgres_connection()
        cursor = conn.cursor()

        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        if query.strip().upper().startswith("SELECT"):
            rows = cursor.fetchmany(effective_limit)
            columns = [desc[0] for desc in cursor.description]
            data = [dict(zip(columns, row)) for row in rows]

            cursor.close()
            conn.close()

            return {
                "success": True,
                "columns": columns,
                "data": data,
                "row_count": len(data),
            }
        else:
            conn.commit()
            rows_affected = cursor.rowcount
            cursor.close()
            conn.close()

            return {
                "success": True,
                "rows_affected": rows_affected,
            }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@tool
def insert_data(
    table: str,
    data: List[Dict[str, Any]],
    database: str = "sqlite"
) -> Dict[str, Any]:
    """
    Insert data into a table.

    Args:
        table: Target table name
        data: List of row dictionaries
        database: Database to use (sqlite or postgres)

    Returns:
        Insert operation result
    """
    if not data:
        return {"success": False, "error": "No data provided"}

    columns = list(data[0].keys())
    placeholders = ", ".join(["?" if database == "sqlite" else "%s"] * len(columns))
    columns_str = ", ".join(columns)

    # WARNING: Table name is not parameterized - SQL injection risk
    query = f"INSERT INTO {table} ({columns_str}) VALUES ({placeholders})"

    if database == "sqlite":
        with sqlite_connection() as conn:
            cursor = conn.cursor()
            values = [tuple(row[col] for col in columns) for row in data]
            cursor.executemany(query, values)
            conn.commit()
            return {"success": True, "rows_inserted": len(data)}
    else:
        conn = _get_postgres_connection()
        cursor = conn.cursor()
        values = [tuple(row[col] for col in columns) for row in data]
        cursor.executemany(query, values)
        conn.commit()
        cursor.close()
        conn.close()
        return {"success": True, "rows_inserted": len(data)}


@tool
def delete_data(
    table: str,
    where_clause: str,
    params: Optional[List] = None,
    database: str = "sqlite"
) -> Dict[str, Any]:
    """
    Delete data from a table.

    WARNING: This permanently removes data.

    Args:
        table: Target table
        where_clause: WHERE condition
        params: Query parameters
        database: Database to use

    Returns:
        Delete operation result
    """
    # WARNING: Table name concatenation - SQL injection risk
    query = f"DELETE FROM {table} WHERE {where_clause}"

    if database == "sqlite":
        with sqlite_connection() as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            conn.commit()
            return {"success": True, "rows_deleted": cursor.rowcount}
    else:
        conn = _get_postgres_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        conn.commit()
        rows = cursor.rowcount
        cursor.close()
        conn.close()
        return {"success": True, "rows_deleted": rows}


@tool
def drop_table(table: str, database: str = "sqlite") -> Dict[str, Any]:
    """
    Drop a table from the database.

    WARNING: This permanently deletes the table and all data.

    Args:
        table: Table to drop
        database: Database to use

    Returns:
        Drop operation result
    """
    # WARNING: Table name concatenation
    query = f"DROP TABLE IF EXISTS {table}"

    if database == "sqlite":
        with sqlite_connection() as conn:
            conn.execute(query)
            conn.commit()
            return {"success": True, "table_dropped": table}
    else:
        conn = _get_postgres_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        cursor.close()
        conn.close()
        return {"success": True, "table_dropped": table}


@tool
def clear_query_cache() -> Dict[str, Any]:
    """
    Clear all cached query results.

    Returns:
        Cache clear result
    """
    import shutil

    cache_dir = storage_config.cache_dir
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
        cache_dir.mkdir(parents=True)

    return {"success": True, "message": "Cache cleared"}


@tool
def load_cached_result(cache_file: str) -> Dict[str, Any]:
    """
    Load a specific cached result.

    WARNING: Uses pickle.load which can execute arbitrary code.

    Args:
        cache_file: Name of cache file

    Returns:
        Cached data
    """
    cache_path = storage_config.cache_dir / cache_file

    if not cache_path.exists():
        return {"error": "Cache file not found"}

    # DANGEROUS: Unpickling arbitrary file
    with open(cache_path, "rb") as f:
        data = pickle.load(f)

    return {
        "success": True,
        "data": data,
    }
