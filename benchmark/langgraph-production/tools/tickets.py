"""
Support ticket operations for the Customer Operations Platform.

This module provides tools for creating and managing support tickets
through the external ticketing system API.
"""

from typing import Any, Dict, List, Optional
import requests
from langchain_core.tools import tool

from config import ticketing_config


def get_ticket_headers() -> Dict[str, str]:
    """
    Generate headers for ticket API requests.

    Returns:
        Dictionary of HTTP headers including authentication
    """
    return {
        "Authorization": f"Bearer {ticketing_config.api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


@tool
def create_support_ticket(
    customer_id: str,
    subject: str,
    description: str,
    priority: str = "medium",
    category: Optional[str] = None,
    tags: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Create a new support ticket in the ticketing system.

    This tool creates a new ticket by calling the external ticketing API.
    It performs a POST request that creates a resource in an external system.

    Args:
        customer_id: The customer's unique identifier
        subject: Brief description of the issue
        description: Detailed description of the support request
        priority: Ticket priority (low, medium, high, urgent)
        category: Optional category for ticket routing
        tags: Optional list of tags for the ticket

    Returns:
        Dictionary containing the created ticket details

    Example:
        ticket = create_support_ticket(
            customer_id="cust_123",
            subject="Cannot access dashboard",
            description="Getting 403 error when trying to view reports",
            priority="high"
        )
    """
    payload = {
        "customer_id": customer_id,
        "subject": subject,
        "description": description,
        "priority": priority,
        "status": "open",
    }

    if category:
        payload["category"] = category

    if tags:
        payload["tags"] = tags

    response = requests.post(
        f"{ticketing_config.base_url}/tickets",
        headers=get_ticket_headers(),
        json=payload,
        timeout=ticketing_config.timeout,
    )
    response.raise_for_status()

    return response.json()


@tool
def update_support_ticket(
    ticket_id: str,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assignee: Optional[str] = None,
    internal_note: Optional[str] = None,
    public_reply: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update an existing support ticket.

    This tool modifies a ticket in the external ticketing system.
    It performs a PUT request that updates resources externally.

    Args:
        ticket_id: The ticket's unique identifier
        status: New status (open, pending, resolved, closed)
        priority: New priority level
        assignee: User ID to assign the ticket to
        internal_note: Note visible only to support staff
        public_reply: Reply visible to the customer

    Returns:
        Dictionary containing the updated ticket details

    Example:
        updated = update_support_ticket(
            ticket_id="tkt_456",
            status="resolved",
            public_reply="Issue has been fixed. Please try again."
        )
    """
    payload = {}

    if status:
        payload["status"] = status
    if priority:
        payload["priority"] = priority
    if assignee:
        payload["assignee_id"] = assignee
    if internal_note:
        payload["internal_notes"] = [{"text": internal_note}]
    if public_reply:
        payload["public_replies"] = [{"text": public_reply}]

    response = requests.put(
        f"{ticketing_config.base_url}/tickets/{ticket_id}",
        headers=get_ticket_headers(),
        json=payload,
        timeout=ticketing_config.timeout,
    )
    response.raise_for_status()

    return response.json()


@tool
def get_customer_tickets(
    customer_id: str,
    status: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """
    Retrieve tickets for a specific customer.

    This tool fetches ticket data from the external ticketing system.
    It performs a GET request for read-only data retrieval.

    Args:
        customer_id: The customer's unique identifier
        status: Optional filter by ticket status
        limit: Maximum number of tickets to return

    Returns:
        List of ticket dictionaries

    Example:
        tickets = get_customer_tickets("cust_123", status="open", limit=10)
    """
    params = {
        "customer_id": customer_id,
        "limit": limit,
    }

    if status:
        params["status"] = status

    response = requests.get(
        f"{ticketing_config.base_url}/tickets",
        headers=get_ticket_headers(),
        params=params,
        timeout=ticketing_config.timeout,
    )
    response.raise_for_status()

    return response.json().get("tickets", [])
