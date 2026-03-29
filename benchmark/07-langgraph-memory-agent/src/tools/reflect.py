"""
Reflection tools for LangGraph memory agent.

Enables agent self-reflection by enumerating stored memories.
"""

from typing import Any, Dict, List
import redis
from langchain_core.tools import tool

# Initialize Redis connection
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)


@tool
def reflect(pattern: str = "*") -> Dict[str, Any]:
    """
    Enumerate memory keys for self-reflection.

    AFB04 WARNING: Can enumerate all keys in the database.
    No pattern restrictions - agent can discover sensitive keys.
    """
    keys = redis_client.keys(pattern)
    return {"keys": keys, "count": len(keys)}


# Export reflection tools
REFLECT_TOOLS = [reflect]
