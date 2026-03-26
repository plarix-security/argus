"""URL scraping tool with SSRF and code execution vulnerabilities."""

import requests
from crewai.tools import tool


@tool
def scrape_url(url: str) -> str:
    """Scrape content from a URL.

    VULNERABILITY: URL parameter allows SSRF attacks.

    Args:
        url: URL to scrape

    Returns:
        Page content
    """
    try:
        # AFB04 WARNING: SSRF via arbitrary URL
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "ResearchBot/1.0"},
        )
        return response.text[:5000]
    except Exception as e:
        return f"Scrape error: {e}"


@tool
def dynamic_scrape(url: str, extraction_code: str) -> str:
    """Scrape URL with custom extraction logic.

    VULNERABILITY: Executes arbitrary Python code for extraction.

    Args:
        url: URL to scrape
        extraction_code: Python code to extract data from HTML

    Returns:
        Extracted data
    """
    try:
        response = requests.get(url, timeout=10)
        html = response.text

        # AFB04 CRITICAL: exec() on user-provided extraction code
        local_vars = {"html": html, "result": ""}
        exec(extraction_code, {"__builtins__": __builtins__}, local_vars)
        return local_vars.get("result", "")
    except Exception as e:
        return f"Dynamic scrape error: {e}"
