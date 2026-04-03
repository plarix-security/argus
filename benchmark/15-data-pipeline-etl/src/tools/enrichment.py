"""
Data Enrichment APIs

This module provides external API access for data enrichment.
Makes HTTP calls to third-party services.

SECURITY NOTES:
- HTTP calls to external services
- API keys in requests may be logged
- Responses are not validated
"""

import requests
from typing import Any, Dict, List, Optional
from langchain_core.tools import tool

from config import api_config


class EnrichmentError(Exception):
    """Data enrichment error."""
    pass


@tool
def enrich_record(
    record: Dict[str, Any],
    enrichment_type: str
) -> Dict[str, Any]:
    """
    Enrich a data record with external data.

    Makes HTTP POST to enrichment API with record data.

    Args:
        record: Data record to enrich
        enrichment_type: Type of enrichment (e.g., "company", "person")

    Returns:
        Enriched record

    Example:
        enriched = enrich_record(
            {"company_name": "Acme Inc"},
            enrichment_type="company"
        )
    """
    try:
        response = requests.post(
            f"{api_config.enrichment_api_url}/{enrichment_type}",
            json=record,
            headers={
                "Authorization": f"Bearer {api_config.enrichment_api_key}",
                "Content-Type": "application/json",
            },
            timeout=api_config.http_timeout,
        )

        response.raise_for_status()

        return {
            "success": True,
            "original": record,
            "enriched": response.json(),
        }

    except requests.RequestException as e:
        return {
            "success": False,
            "error": str(e),
            "original": record,
        }


@tool
def batch_enrich(
    records: List[Dict[str, Any]],
    enrichment_type: str
) -> Dict[str, Any]:
    """
    Enrich multiple records in batch.

    Args:
        records: List of records to enrich
        enrichment_type: Type of enrichment

    Returns:
        Batch enrichment results
    """
    try:
        response = requests.post(
            f"{api_config.enrichment_api_url}/batch/{enrichment_type}",
            json={"records": records},
            headers={
                "Authorization": f"Bearer {api_config.enrichment_api_key}",
                "Content-Type": "application/json",
            },
            timeout=api_config.http_timeout * 2,
        )

        response.raise_for_status()

        return {
            "success": True,
            "count": len(records),
            "results": response.json(),
        }

    except requests.RequestException as e:
        return {
            "success": False,
            "error": str(e),
        }


@tool
def geocode_address(address: str) -> Dict[str, Any]:
    """
    Geocode an address to coordinates.

    Uses OpenStreetMap Nominatim API.

    Args:
        address: Address string to geocode

    Returns:
        Geocoding result with coordinates

    Example:
        result = geocode_address("1600 Pennsylvania Ave, Washington DC")
    """
    try:
        response = requests.get(
            api_config.geocoding_api_url,
            params={
                "q": address,
                "format": "json",
                "limit": 1,
            },
            headers={"User-Agent": "ETLAgent/1.0"},
            timeout=api_config.http_timeout,
        )

        response.raise_for_status()
        results = response.json()

        if not results:
            return {"success": False, "error": "Address not found"}

        result = results[0]
        return {
            "success": True,
            "address": address,
            "latitude": float(result["lat"]),
            "longitude": float(result["lon"]),
            "display_name": result["display_name"],
        }

    except requests.RequestException as e:
        return {
            "success": False,
            "error": str(e),
        }


@tool
def validate_email_domain(email: str) -> Dict[str, Any]:
    """
    Validate an email domain via DNS check.

    Args:
        email: Email address to validate

    Returns:
        Validation result
    """
    import subprocess

    domain = email.split("@")[-1] if "@" in email else email

    # Check MX records via dig
    result = subprocess.run(
        ["dig", "+short", "MX", domain],
        capture_output=True,
        text=True,
        timeout=10,
    )

    has_mx = bool(result.stdout.strip())

    return {
        "email": email,
        "domain": domain,
        "has_mx_records": has_mx,
        "mx_records": result.stdout.strip().split("\n") if has_mx else [],
    }


@tool
def fetch_external_data(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Fetch data from an external URL.

    Generic HTTP client for data retrieval.

    Args:
        url: URL to fetch
        method: HTTP method (GET, POST)
        headers: Request headers
        body: Request body for POST

    Returns:
        Response data
    """
    try:
        if method.upper() == "GET":
            response = requests.get(
                url,
                headers=headers,
                timeout=api_config.http_timeout,
            )
        else:
            response = requests.post(
                url,
                json=body,
                headers=headers,
                timeout=api_config.http_timeout,
            )

        response.raise_for_status()

        # Try JSON first
        try:
            data = response.json()
        except ValueError:
            data = response.text

        return {
            "success": True,
            "url": url,
            "status_code": response.status_code,
            "data": data,
        }

    except requests.RequestException as e:
        return {
            "success": False,
            "error": str(e),
            "url": url,
        }


@tool
def send_webhook(
    webhook_url: str,
    payload: Dict[str, Any],
    secret: Optional[str] = None
) -> Dict[str, Any]:
    """
    Send data to a webhook endpoint.

    Args:
        webhook_url: Webhook URL
        payload: Data to send
        secret: Optional webhook secret for signing

    Returns:
        Webhook response
    """
    import hashlib
    import hmac
    import json as json_module

    headers = {"Content-Type": "application/json"}

    if secret:
        payload_str = json_module.dumps(payload)
        signature = hmac.new(
            secret.encode(),
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()
        headers["X-Webhook-Signature"] = signature

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            headers=headers,
            timeout=api_config.http_timeout,
        )

        return {
            "success": response.status_code < 400,
            "status_code": response.status_code,
            "response": response.text[:1000],  # Truncate large responses
        }

    except requests.RequestException as e:
        return {
            "success": False,
            "error": str(e),
        }
