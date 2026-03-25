"""
CRM integration for the Customer Operations Platform.

This module provides tools for synchronizing data with the external
CRM system (Salesforce-style API).
"""

from typing import Any, Dict, List, Optional
import requests
from langchain_core.tools import tool

from config import crm_config


def get_crm_headers() -> Dict[str, str]:
    """
    Generate headers for CRM API requests.

    Returns:
        Dictionary of HTTP headers including OAuth token
    """
    return {
        "Authorization": f"Bearer {crm_config.access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def refresh_access_token() -> str:
    """
    Refresh the CRM OAuth access token.

    Returns:
        New access token string
    """
    response = requests.post(
        f"{crm_config.base_url}/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": crm_config.client_id,
            "client_secret": crm_config.client_secret,
        }
    )
    response.raise_for_status()
    return response.json()["access_token"]


@tool
def sync_to_crm(
    customer_data: Dict[str, Any],
    create_if_missing: bool = True
) -> Dict[str, Any]:
    """
    Sync customer data to the external CRM system.

    This tool pushes customer information to the CRM via API.
    It performs POST/PATCH requests that modify external system state.

    Args:
        customer_data: Dictionary containing customer fields to sync
        create_if_missing: Create new record if customer doesn't exist

    Returns:
        Dictionary containing sync results and CRM record ID

    Example:
        result = sync_to_crm({
            "customer_id": "cust_123",
            "email": "customer@example.com",
            "company": "Acme Corp",
            "plan": "enterprise"
        })
    """
    customer_id = customer_data.get("customer_id")

    # First, check if customer exists in CRM
    search_response = requests.get(
        f"{crm_config.base_url}/sobjects/Contact/search",
        headers=get_crm_headers(),
        params={"q": f"External_ID__c = '{customer_id}'"}
    )

    crm_payload = {
        "External_ID__c": customer_id,
        "Email": customer_data.get("email"),
        "Company": customer_data.get("company"),
        "Plan__c": customer_data.get("plan"),
        "Last_Sync__c": True,
    }

    if search_response.status_code == 200 and search_response.json().get("records"):
        # Update existing record
        crm_id = search_response.json()["records"][0]["Id"]
        response = requests.patch(
            f"{crm_config.base_url}/sobjects/Contact/{crm_id}",
            headers=get_crm_headers(),
            json=crm_payload
        )
        response.raise_for_status()
        return {"status": "updated", "crm_id": crm_id}

    elif create_if_missing:
        # Create new record
        response = requests.post(
            f"{crm_config.base_url}/sobjects/Contact",
            headers=get_crm_headers(),
            json=crm_payload
        )
        response.raise_for_status()
        return {"status": "created", "crm_id": response.json().get("id")}

    else:
        return {"status": "not_found", "customer_id": customer_id}


@tool
def get_crm_record(crm_id: str) -> Dict[str, Any]:
    """
    Retrieve a record from the CRM system.

    Fetches customer data from the external CRM by ID.
    This is a read-only operation via GET request.

    Args:
        crm_id: The CRM system's internal record ID

    Returns:
        Dictionary containing contact record data

    Example:
        record = get_crm_record("003XXXXXXXXXXXXXXX")
    """
    response = requests.get(
        f"{crm_config.base_url}/sobjects/Contact/{crm_id}",
        headers=get_crm_headers()
    )
    response.raise_for_status()

    return response.json()


@tool
def bulk_sync_to_crm(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Bulk sync multiple customer records to CRM.

    Performs batch upsert operation to the CRM system.
    This tool sends multiple records in a single API call.

    Args:
        records: List of customer data dictionaries to sync

    Returns:
        Dictionary with batch results and any errors

    Example:
        results = bulk_sync_to_crm([
            {"customer_id": "cust_1", "email": "a@example.com"},
            {"customer_id": "cust_2", "email": "b@example.com"}
        ])
    """
    crm_records = []
    for record in records:
        crm_records.append({
            "attributes": {"type": "Contact"},
            "External_ID__c": record.get("customer_id"),
            "Email": record.get("email"),
            "Company": record.get("company"),
        })

    response = requests.post(
        f"{crm_config.base_url}/composite/sobjects",
        headers=get_crm_headers(),
        json={"records": crm_records, "allOrNone": False}
    )
    response.raise_for_status()

    results = response.json()
    successes = sum(1 for r in results if r.get("success"))
    failures = sum(1 for r in results if not r.get("success"))

    return {
        "total": len(records),
        "successes": successes,
        "failures": failures,
        "details": results,
    }
