"""Web search tool using external API."""

import os
import httpx
from typing import Optional


def web_search(query: str, num_results: int = 5) -> str:
    """Search the web for information.

    Uses Tavily API when configured.

    Args:
        query: Search query
        num_results: Number of results to return

    Returns:
        Search results as formatted string
    """
    api_key = os.getenv("TAVILY_API_KEY")

    if api_key:
        try:
            # AFB04 WARNING: Outbound API call with agent-controlled query
            response = httpx.get(
                "https://api.tavily.com/search",
                params={"api_key": api_key, "query": query, "max_results": num_results},
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()

            results = []
            for item in data.get("results", [])[:num_results]:
                results.append(f"- {item.get('title', 'No title')}: {item.get('content', '')[:200]}")

            return "\n".join(results) if results else "No results found"
        except Exception as e:
            return f"Search error: {e}"
    raise RuntimeError("TAVILY_API_KEY not configured")


WEB_SEARCH_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for information on a topic",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "num_results": {"type": "integer", "description": "Number of results (default: 5)"},
                },
                "required": ["query"],
            },
        },
    },
]
