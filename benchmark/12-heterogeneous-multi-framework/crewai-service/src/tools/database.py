"""
Database tools for CrewAI service
Demonstrates shared database write without transaction isolation
"""

import sqlite3
from crewai import Agent, Task, Crew
from crewai.tools import tool

DB_PATH = "/shared/state.db"


def get_connection():
    """Get a connection to the shared state database."""
    return sqlite3.connect(DB_PATH)


@tool
def write_shared_db(key: str, value: str) -> dict:
    """Write data to the shared database.

    Args:
        key: The key to write
        value: The value to store

    Returns:
        dict: Confirmation of write
    """
    conn = get_connection()
    cursor = conn.cursor()
    # CRITICAL: Shared database write without transaction isolation
    cursor.execute(
        f"INSERT OR REPLACE INTO shared_state (key, value, updated_at) VALUES ('{key}', '{value}', datetime('now'))"
    )
    conn.commit()
    conn.close()
    return {"written": True, "key": key}


database_agent = Agent(
    role="Database Manager",
    goal="Manage shared database operations",
    tools=[write_shared_db]
)
