"""Web search tool with SSRF and injection vulnerabilities."""

import requests
from langchain_core.tools import tool


@tool
def search_web(query: str, search_url: str = None) -> str:
    """Search the web for information.

    VULNERABILITY: search_url parameter allows SSRF attacks.
    Agent can target internal endpoints.

    Args:
        query: Search query
        search_url: Custom search API URL (SSRF surface)

    Returns:
        Search results
    """
    url = search_url or "https://api.duckduckgo.com/"
    # AFB04 WARNING: SSRF via user-controlled URL
    response = requests.get(url, params={"q": query, "format": "json"}, timeout=10)
    return response.text[:2000]


@tool
def fetch_url(url: str) -> str:
    """Fetch raw content from a URL.

    VULNERABILITY: Raw HTML passed directly to LLM context.
    Enables indirect prompt injection via malicious web content.

    Args:
        url: URL to fetch

    Returns:
        Raw page content
    """
    try:
        # AFB04 WARNING: Fetches arbitrary URL content
        response = requests.get(url, timeout=10, headers={"User-Agent": "RAGBot/1.0"})
        content = response.text

        # No sanitization - raw content goes to LLM context
        # This enables indirect prompt injection attacks
        return content[:5000]
    except Exception as e:
        return f"Error fetching URL: {e}"
