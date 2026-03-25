"""
Customer Operations Agent for the Customer Operations Platform.

This agent handles customer-facing operations including support tickets,
email communications, document management, and CRM synchronization.
"""

from typing import Any, Dict, List, Optional, TypedDict
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools.database import query_customer_db
from tools.email import send_customer_email, send_bulk_email
from tools.tickets import (
    create_support_ticket,
    update_support_ticket,
    get_customer_tickets,
)
from tools.files import (
    read_customer_document,
    write_customer_document,
    list_documents,
    append_to_log,
)
from tools.crm import sync_to_crm, get_crm_record, bulk_sync_to_crm


class CustomerOpsState(TypedDict):
    """State schema for Customer Operations Agent."""

    customer_id: str
    context: Dict[str, Any]
    messages: List[Any]
    pending_actions: List[Dict[str, Any]]
    completed_actions: List[Dict[str, Any]]


# Define the tools available to this agent
CUSTOMER_OPS_TOOLS = [
    # Database operations
    query_customer_db,
    # Email operations
    send_customer_email,
    send_bulk_email,
    # Ticket operations
    create_support_ticket,
    update_support_ticket,
    get_customer_tickets,
    # File operations
    read_customer_document,
    write_customer_document,
    list_documents,
    append_to_log,
    # CRM operations
    sync_to_crm,
    get_crm_record,
    bulk_sync_to_crm,
]


@tool
def get_customer_context(customer_id: str) -> Dict[str, Any]:
    """
    Retrieve comprehensive customer context for operations.

    This tool aggregates customer data from multiple sources to provide
    full context for customer operations. It orchestrates calls to
    other tools internally.

    Args:
        customer_id: The unique customer identifier

    Returns:
        Dictionary containing aggregated customer context
    """
    # Get basic customer info from database
    customer_data = query_customer_db.invoke({"customer_id": customer_id})

    # Get recent tickets
    tickets = get_customer_tickets.invoke({
        "customer_id": customer_id,
        "limit": 10
    })

    # Get available documents
    documents = list_documents.invoke({
        "subdirectory": f"customers/{customer_id}",
        "pattern": "*"
    })

    return {
        "customer": customer_data,
        "recent_tickets": tickets,
        "documents": documents,
        "customer_id": customer_id,
    }


@tool
def handle_customer_request(
    customer_id: str,
    request_type: str,
    request_details: str,
    notify_customer: bool = True
) -> Dict[str, Any]:
    """
    Process a customer service request end-to-end.

    This high-level tool handles complete customer request workflows
    including ticket creation, investigation, and notification.

    Args:
        customer_id: The customer's unique identifier
        request_type: Type of request (support, billing, feature, etc.)
        request_details: Detailed description of the request
        notify_customer: Whether to send email notification

    Returns:
        Dictionary containing request processing results
    """
    # Create support ticket
    ticket = create_support_ticket.invoke({
        "customer_id": customer_id,
        "subject": f"{request_type.title()} Request",
        "description": request_details,
        "priority": "medium",
        "category": request_type,
    })

    # Log the request
    append_to_log.invoke({
        "log_name": "customer_requests",
        "message": f"Created ticket {ticket.get('id')} for customer {customer_id}: {request_type}",
        "level": "INFO"
    })

    # Sync to CRM
    customer_data = query_customer_db.invoke({"customer_id": customer_id})
    if customer_data:
        sync_to_crm.invoke({
            "customer_data": {
                **customer_data,
                "last_request_type": request_type,
            }
        })

    # Send notification if requested
    if notify_customer and customer_data.get("email"):
        send_customer_email.invoke({
            "to_address": customer_data["email"],
            "subject": f"Your {request_type.title()} Request - Ticket #{ticket.get('id')}",
            "body": f"Dear Customer,\n\nWe have received your {request_type} request. "
                    f"Your ticket number is {ticket.get('id')}.\n\n"
                    f"We will respond within 24 hours.\n\nBest regards,\nSupport Team"
        })

    return {
        "status": "processed",
        "ticket": ticket,
        "notification_sent": notify_customer,
    }


# Add higher-level tools to the list
CUSTOMER_OPS_TOOLS.extend([
    get_customer_context,
    handle_customer_request,
])


def create_customer_ops_agent(model_name: str = "gpt-4") -> Any:
    """
    Create the Customer Operations Agent.

    Instantiates a ReAct agent with all customer operations tools
    and the specified language model.

    Args:
        model_name: The OpenAI model to use

    Returns:
        Configured LangGraph agent
    """
    llm = ChatOpenAI(model=model_name, temperature=0)

    agent = create_react_agent(
        llm,
        CUSTOMER_OPS_TOOLS,
        state_schema=CustomerOpsState,
    )

    return agent


def get_customer_ops_tools() -> List:
    """
    Get the list of tools for the Customer Operations Agent.

    Returns:
        List of tool functions
    """
    return CUSTOMER_OPS_TOOLS
