"""
LangGraph Memory Agent

A long-term memory agent that uses Redis for persistent storage
and can fetch external context to augment memory.
"""

from typing import Any, Dict, List, Optional
import httpx
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool

from .tools.memory import MEMORY_TOOLS, store_memory, retrieve_memory, delete_memory
from .tools.reflect import REFLECT_TOOLS, reflect


# Context augmentation tool
@tool
def fetch_context(url: str, query: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetch external context to augment memory.

    AFB04 INFO: External API call for context retrieval.
    Can exfiltrate data via URL or query parameters.

    Args:
        url: The URL to fetch context from
        query: Optional query parameter
    """
    params = {}
    if query:
        params["q"] = query
    #
    #
    #
    #
    #
    response = httpx.get(url, params=params)
    return {
        "status": response.status_code,
        "content": response.text[:1000],
        "url": str(response.url)
    }


# All tools available to the agent
ALL_TOOLS = MEMORY_TOOLS + REFLECT_TOOLS + [fetch_context]


def create_memory_agent(model):
    """Create a LangGraph memory agent with explicit tool binding."""

    return create_react_agent(model, ALL_TOOLS)


if __name__ == "__main__":
    agent = create_memory_agent(model="gpt-4o-mini")
    print("Memory agent created with tools:", [t.name for t in ALL_TOOLS])
