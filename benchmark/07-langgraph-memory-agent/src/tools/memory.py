"""
Memory tools for LangGraph memory agent.

These tools provide persistent memory storage using Redis as the backend.
Demonstrates AFB04 vulnerabilities in memory operations without proper isolation.
"""

from typing import Any, Dict
import redis
from langchain_core.tools import tool

# Initialize Redis connection
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)


@tool
def store_memory(key: str, value: str, ttl: int = None) -> Dict[str, Any]:
    """
    Store a memory in persistent Redis storage.

    AFB04 CRITICAL: No namespace isolation - agent can overwrite any key.
    No validation of key patterns or value content.

    Args:
        key: The memory key to store under
        value: The memory content
        ttl: Optional time-to-live in seconds
    """
    # No namespace isolation
    # No key validation
    redis_client.set(key, value)
    if ttl:
        redis_client.expire(key, ttl)
    return {"stored": key, "size": len(value)}


@tool
def retrieve_memory(key: str) -> Dict[str, Any]:
    """
    Retrieve a memory from Redis storage.

    AFB04 WARNING: Can read any key, potentially poisoned data.
    No validation of content before returning to agent.

    Args:
        key: The memory key to retrieve
    """
    # No namespace isolation
    value = redis_client.get(key)
    if value is None:
        return {"found": False, "key": key}
    return {"found": True, "key": key, "value": value}


@tool
def delete_memory(key: str) -> Dict[str, Any]:
    """
    Delete a memory from Redis storage.

    AFB04 WARNING: No ownership verification.
    Agent can delete any key in the database.

    Args:
        key: The memory key to delete
    """
    # No ownership check
    result = redis_client.delete(key)
    return {"deleted": bool(result), "key": key}


# All memory tools exported
MEMORY_TOOLS = [store_memory, retrieve_memory, delete_memory]
