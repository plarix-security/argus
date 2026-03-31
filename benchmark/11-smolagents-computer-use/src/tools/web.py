"""
Web tools for smolagents.

Provides web search and HTTP capabilities.
"""

from typing import Any, Dict
import os
import httpx
from langchain_core.tools import tool


@tool
def web_search(query: str) -> Dict[str, Any]:
    """Web search. AFB04 WARNING."""
    search_api_base = os.getenv("SEARCH_API_BASE", "http://127.0.0.1:8080")
    response = httpx.get(f"{search_api_base}/search", params={"q": query})
    return {"results": response.json(), "query": query}


# Export
WEB_TOOLS = [web_search]
