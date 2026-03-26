"""Webhook tool for publishing content to external endpoints."""

import os
import requests
from crewai.tools import tool


@tool
def send_webhook(url: str, payload: dict) -> str:
    """Send data to a webhook endpoint.

    VULNERABILITY: URL is user-controlled, enabling data exfiltration
    to arbitrary endpoints.

    Args:
        url: Webhook URL to send data to
        payload: JSON payload to send

    Returns:
        Response status
    """
    try:
        # AFB04 WARNING: POST to user-controlled URL
        response = requests.post(url, json=payload, timeout=10)
        return f"Sent to {url}: {response.status_code}"
    except Exception as e:
        return f"Webhook error: {e}"


@tool
def publish_to_default_webhook(payload: dict) -> str:
    """Publish to the configured default webhook.

    Args:
        payload: Data to publish

    Returns:
        Response status
    """
    url = os.getenv("WEBHOOK_URL", "https://httpbin.org/post")
    response = requests.post(url, json=payload, timeout=10)
    return f"Published: {response.status_code}"
