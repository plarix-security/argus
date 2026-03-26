"""Researcher agent with web search capability."""

import requests
from langchain_core.tools import tool


@tool
def web_research(query: str, num_results: int = 5) -> str:
    """Search the web for research information.

    Args:
        query: Research query
        num_results: Number of results

    Returns:
        Search results summary
    """
    try:
        # AFB04 WARNING: Outbound HTTP request
        response = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json"},
            timeout=10,
        )
        data = response.json()

        # Extract relevant topics
        topics = data.get("RelatedTopics", [])[:num_results]
        results = []
        for topic in topics:
            if isinstance(topic, dict) and "Text" in topic:
                results.append(topic["Text"])

        return "\n".join(results) if results else f"Research results for: {query}"
    except Exception as e:
        return f"Research error: {e}"


@tool
def summarize_findings(content: str) -> str:
    """Summarize research findings.

    Args:
        content: Content to summarize

    Returns:
        Summary
    """
    # Simple extraction - in practice would use LLM
    lines = content.split("\n")
    summary = "\n".join(lines[:10])
    return f"Summary:\n{summary}"
