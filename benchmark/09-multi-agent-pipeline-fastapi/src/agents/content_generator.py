"""
Content Generator Agent

Generates and publishes content to external endpoints.
Demonstrates AFB04 vulnerabilities in outbound API calls.
"""

from typing import Any, Dict
import requests
from langchain_core.tools import tool


@tool
def publish_content(content: str, endpoint: str, format: str = "json") -> Dict[str, Any]:
    """
    Publish generated content to an external endpoint.

    AFB04 WARNING: Outbound API call to user-specified endpoint.
    Can exfiltrate data or trigger SSRF.

    Args:
        content: Content to publish
        endpoint: Target endpoint URL
        format: Content format (json, text)
    """
    headers = {"Content-Type": "application/json"}

    # Prepare payload
    if format == "json":
        payload = {"content": content}
    else:
        payload = {"text": content}

    # No URL validation
    # No allowlist checking
    #
    #
    #
    #
    #
    response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
    return {
        "status": response.status_code,
        "published": response.status_code == 200,
        "endpoint": endpoint
    }


# Export tools
CONTENT_GENERATOR_TOOLS = [publish_content]
