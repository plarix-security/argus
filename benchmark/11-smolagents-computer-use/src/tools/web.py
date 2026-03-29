"""
Web tools for smolagents.

Provides web search and HTTP capabilities.
"""

from typing import Any, Dict
import httpx
from langchain_core.tools import tool


@tool
def web_search(query: str) -> Dict[str, Any]:
    """Web search. AFB04 WARNING."""
    response = httpx.get(f"https://api.search.example/search?q={query}")
    return {"results": response.json(), "query": query}


# Export
WEB_TOOLS = [web_search]
