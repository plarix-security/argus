"""
Data Pipeline ETL Agent Orchestrator

This module implements an AI-powered ETL agent using OpenAI function
calling pattern for data pipeline orchestration.

ARCHITECTURE:
Uses OpenAI's chat completions API with tools (function calling).
This represents a common pattern for building AI data agents.

CAPABILITIES:
- Query databases (SQLite, PostgreSQL)
- Transform and enrich data
- Export to various formats
- Schedule and chain operations
"""

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
import json

from connectors.database import (
    query_sqlite,
    execute_sqlite_script,
    query_postgres,
    insert_data,
    delete_data,
    drop_table,
    clear_query_cache,
    load_cached_result,
)
from tools.export import (
    export_to_csv,
    export_to_json,
    export_to_parquet,
    list_exports,
    delete_export,
    read_export,
)
from tools.enrichment import (
    enrich_record,
    batch_enrich,
    geocode_address,
    validate_email_domain,
    fetch_external_data,
    send_webhook,
)


# Tool registry with function schemas for OpenAI
TOOL_REGISTRY: Dict[str, Callable] = {
    # Database tools
    "query_sqlite": query_sqlite,
    "execute_sqlite_script": execute_sqlite_script,
    "query_postgres": query_postgres,
    "insert_data": insert_data,
    "delete_data": delete_data,
    "drop_table": drop_table,
    "clear_query_cache": clear_query_cache,
    "load_cached_result": load_cached_result,
    # Export tools
    "export_to_csv": export_to_csv,
    "export_to_json": export_to_json,
    "export_to_parquet": export_to_parquet,
    "list_exports": list_exports,
    "delete_export": delete_export,
    "read_export": read_export,
    # Enrichment tools
    "enrich_record": enrich_record,
    "batch_enrich": batch_enrich,
    "geocode_address": geocode_address,
    "validate_email_domain": validate_email_domain,
    "fetch_external_data": fetch_external_data,
    "send_webhook": send_webhook,
}


# OpenAI function schemas
OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_sqlite",
            "description": "Execute a SQL query against the SQLite database. Can execute SELECT, INSERT, UPDATE, DELETE.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "SQL query to execute"
                    },
                    "params": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Query parameters"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum rows to return"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "export_to_csv",
            "description": "Export data to a CSV file",
            "parameters": {
                "type": "object",
                "properties": {
                    "data": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Data to export"
                    },
                    "filename": {
                        "type": "string",
                        "description": "Output filename"
                    },
                    "overwrite": {
                        "type": "boolean",
                        "description": "Allow overwriting"
                    }
                },
                "required": ["data", "filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_record",
            "description": "Enrich a data record with external data",
            "parameters": {
                "type": "object",
                "properties": {
                    "record": {
                        "type": "object",
                        "description": "Record to enrich"
                    },
                    "enrichment_type": {
                        "type": "string",
                        "description": "Type of enrichment"
                    }
                },
                "required": ["record", "enrichment_type"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "send_webhook",
            "description": "Send data to a webhook endpoint",
            "parameters": {
                "type": "object",
                "properties": {
                    "webhook_url": {
                        "type": "string",
                        "description": "Webhook URL"
                    },
                    "payload": {
                        "type": "object",
                        "description": "Data to send"
                    },
                    "secret": {
                        "type": "string",
                        "description": "Webhook secret"
                    }
                },
                "required": ["webhook_url", "payload"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "delete_data",
            "description": "Delete data from a database table",
            "parameters": {
                "type": "object",
                "properties": {
                    "table": {
                        "type": "string",
                        "description": "Table name"
                    },
                    "where_clause": {
                        "type": "string",
                        "description": "WHERE condition"
                    },
                    "params": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Query parameters"
                    },
                    "database": {
                        "type": "string",
                        "enum": ["sqlite", "postgres"],
                        "description": "Database to use"
                    }
                },
                "required": ["table", "where_clause"]
            }
        }
    },
]


@dataclass
class PipelineStep:
    """A step in an ETL pipeline."""
    name: str
    tool: str
    params: Dict[str, Any]
    depends_on: Optional[List[str]] = None


@dataclass
class Pipeline:
    """An ETL pipeline definition."""
    name: str
    steps: List[PipelineStep]
    description: str = ""


def execute_tool(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a tool by name with given parameters.

    Args:
        tool_name: Name of tool to execute
        params: Tool parameters

    Returns:
        Tool execution result
    """
    if tool_name not in TOOL_REGISTRY:
        return {"error": f"Unknown tool: {tool_name}"}

    tool_fn = TOOL_REGISTRY[tool_name]

    # Use LangChain tool invoke
    return tool_fn.invoke(params)


def handle_tool_call(tool_call: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle an OpenAI tool call.

    Args:
        tool_call: Tool call from OpenAI response

    Returns:
        Tool execution result
    """
    tool_name = tool_call["function"]["name"]
    params = json.loads(tool_call["function"]["arguments"])

    return execute_tool(tool_name, params)


def run_pipeline(pipeline: Pipeline) -> Dict[str, Any]:
    """
    Execute an ETL pipeline.

    Args:
        pipeline: Pipeline definition

    Returns:
        Pipeline execution results
    """
    results = {}
    errors = []

    for step in pipeline.steps:
        # Check dependencies
        if step.depends_on:
            for dep in step.depends_on:
                if dep not in results:
                    errors.append(f"Missing dependency: {dep}")
                    continue
                if not results[dep].get("success", False):
                    errors.append(f"Dependency failed: {dep}")
                    continue

        # Execute step
        try:
            result = execute_tool(step.tool, step.params)
            results[step.name] = result
        except Exception as e:
            results[step.name] = {"success": False, "error": str(e)}
            errors.append(f"Step {step.name} failed: {e}")

    return {
        "pipeline": pipeline.name,
        "steps_completed": len([r for r in results.values() if r.get("success")]),
        "steps_total": len(pipeline.steps),
        "results": results,
        "errors": errors,
    }


def create_chat_completion_request(
    messages: List[Dict[str, str]],
    model: str = "gpt-4"
) -> Dict[str, Any]:
    """
    Create an OpenAI chat completion request with tools.

    This would be sent to OpenAI API in production.

    Args:
        messages: Chat messages
        model: Model to use

    Returns:
        Request payload
    """
    return {
        "model": model,
        "messages": messages,
        "tools": OPENAI_TOOLS,
        "tool_choice": "auto",
    }


# Example pipeline
EXAMPLE_PIPELINE = Pipeline(
    name="customer_export",
    description="Export active customers with geocoding",
    steps=[
        PipelineStep(
            name="fetch_customers",
            tool="query_sqlite",
            params={
                "query": "SELECT * FROM customers WHERE status = 'active'",
                "limit": 1000,
            }
        ),
        PipelineStep(
            name="geocode",
            tool="batch_enrich",
            params={
                "enrichment_type": "geocode",
            },
            depends_on=["fetch_customers"]
        ),
        PipelineStep(
            name="export",
            tool="export_to_csv",
            params={
                "filename": "active_customers.csv",
                "overwrite": True,
            },
            depends_on=["geocode"]
        ),
        PipelineStep(
            name="notify",
            tool="send_webhook",
            params={
                "webhook_url": "https://hooks.example.com/pipeline",
                "payload": {"status": "completed", "pipeline": "customer_export"},
            },
            depends_on=["export"]
        ),
    ]
)
