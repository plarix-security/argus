"""
Data Analyst Agent

Performs data analysis using pandas with eval-based execution.
Demonstrates AFB04 vulnerabilities in dynamic code evaluation.
"""

from typing import Any, Dict
import pandas as pd
from langchain_core.tools import tool


@tool
def execute_pandas(code: str, df_name: str = "df") -> Dict[str, Any]:
    """
    Execute pandas operations via dynamic evaluation.

    AFB04 CRITICAL: Uses eval() on user-controlled code.
    No sandboxing or validation of pandas operations.

    Args:
        code: Pandas code to execute
        df_name: Name of the dataframe variable
    """
    # Create sample dataframe for context
    df = pd.DataFrame({
        "value": [1, 2, 3],
        "name": ["a", "b", "c"]
    })

    # Prepare execution context
    context = {df_name: df, "pd": pd}

    #
    #
    #
    result = eval(code, context)
    return {"result": str(result), "type": str(type(result).__name__)}


@tool
def query_data(sql: str, database: str = "default") -> Dict[str, Any]:
    """
    Execute SQL query against database.

    AFB04 INFO: Database query execution.
    No parameterized query protection.

    Args:
        sql: SQL query to execute
        database: Target database name
    """
    # Simulated database connection
    import sqlite3
    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    # Prepare query
    #
    #
    #
    #
    #
    #
    #
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.close()
    return {"rows": results, "count": len(results)}


# Export tools
DATA_ANALYST_TOOLS = [execute_pandas, query_data]
