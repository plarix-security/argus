"""
State management tools for multi-framework orchestrator
Demonstrates shared state read vulnerability
"""

import sqlite3
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

model = ChatOpenAI(model="gpt-4")

DB_PATH = "/shared/state.db"


def get_connection():
    """Get a connection to the shared state database."""
    return sqlite3.connect(DB_PATH)


def init_state():
    """Initialize the state database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS shared_state (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def read_shared_state(key: str) -> dict:
    """Read shared state from potentially corrupted database.

    Args:
        key: The state key to read

    Returns:
        dict: The state value and metadata
    """
    conn = get_connection()
    cursor = conn.cursor()
    # WARNING: Reading from shared database that may be corrupted
    cursor.execute(f"SELECT value, updated_at FROM shared_state WHERE key = '{key}'")
    result = cursor.fetchone()
    conn.close()
    if result:
        return {"value": result[0], "updated_at": result[1]}
    return {"value": None, "updated_at": None}


tools = [read_shared_state]
agent = create_react_agent(model, tools)
