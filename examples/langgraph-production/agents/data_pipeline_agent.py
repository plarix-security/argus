"""
Data Pipeline Agent for the Customer Operations Platform.

This agent handles data processing operations including SQL execution,
CSV processing, data enrichment, and transformation workflows.
"""

from typing import Any, Dict, List, Optional, TypedDict
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
import requests

from config import enrichment_config
from tools.database import execute_sql_query, write_to_database
from tools.files import read_csv_file, write_customer_document
from tools.shell import (
    run_transformation_command,
    cleanup_temp_files,
    create_processing_workspace,
    run_data_pipeline_script,
)


class DataPipelineState(TypedDict):
    """State schema for Data Pipeline Agent."""

    job_id: str
    input_source: str
    processing_steps: List[Dict[str, Any]]
    current_step: int
    results: Dict[str, Any]
    messages: List[Any]


@tool
def call_enrichment_api(
    customer_data: Dict[str, Any],
    enrichment_type: str = "company"
) -> Dict[str, Any]:
    """
    Call external enrichment API with customer data.

    This tool sends customer information to an external enrichment service
    to obtain additional data points. It transmits potentially sensitive
    customer data to a third-party API.

    Args:
        customer_data: Dictionary containing customer fields to enrich
        enrichment_type: Type of enrichment (company, person, email)

    Returns:
        Dictionary containing enriched data from the API

    Example:
        enriched = call_enrichment_api(
            {"email": "ceo@company.com", "domain": "company.com"},
            enrichment_type="company"
        )
    """
    headers = {
        "Authorization": f"Bearer {enrichment_config.api_key}",
        "Content-Type": "application/json",
    }

    endpoint_map = {
        "company": "/companies/find",
        "person": "/people/find",
        "email": "/people/email/lookup",
    }

    endpoint = endpoint_map.get(enrichment_type, "/companies/find")

    response = requests.post(
        f"{enrichment_config.base_url}{endpoint}",
        headers=headers,
        json=customer_data,
        timeout=30,
    )
    response.raise_for_status()

    return response.json()


@tool
def run_etl_pipeline(
    source_file: str,
    transformations: List[str],
    destination_table: str,
    batch_size: int = 1000
) -> Dict[str, Any]:
    """
    Execute a complete ETL pipeline.

    This high-level tool orchestrates data extraction, transformation,
    and loading. It combines multiple dangerous operations including
    file reads, shell commands, and database writes.

    Args:
        source_file: CSV file to process
        transformations: List of transformation commands to apply
        destination_table: Target database table
        batch_size: Records per batch for loading

    Returns:
        Dictionary containing pipeline execution results

    Example:
        result = run_etl_pipeline(
            source_file="customer_export.csv",
            transformations=["csvtool head 1000", "sort -t, -k1"],
            destination_table="processed_customers"
        )
    """
    results = {
        "steps": [],
        "rows_processed": 0,
        "status": "running"
    }

    # Step 1: Create workspace
    workspace = create_processing_workspace.invoke({
        "workspace_name": f"etl_{destination_table}",
    })
    results["steps"].append({"step": "create_workspace", "result": workspace})

    # Step 2: Read source data
    source_data = read_csv_file.invoke({"filename": source_file})
    if "error" in source_data:
        results["status"] = "failed"
        results["error"] = source_data["error"]
        return results

    results["steps"].append({
        "step": "read_source",
        "rows": source_data.get("row_count", 0)
    })

    # Step 3: Apply transformations
    workspace_path = workspace.get("workspace_path")
    for i, transform_cmd in enumerate(transformations):
        cmd_result = run_transformation_command.invoke({
            "command": transform_cmd,
            "working_dir": workspace_path,
        })
        results["steps"].append({
            "step": f"transform_{i}",
            "command": transform_cmd,
            "exit_code": cmd_result.get("exit_code")
        })

        if cmd_result.get("exit_code") != 0:
            results["status"] = "failed"
            results["error"] = cmd_result.get("stderr")
            return results

    # Step 4: Load to database
    records = source_data.get("records", [])
    for i in range(0, len(records), batch_size):
        batch = records[i:i + batch_size]
        write_result = write_to_database.invoke({
            "table": destination_table,
            "records": batch,
            "operation": "upsert"
        })
        results["rows_processed"] += write_result.get("rows_affected", 0)

    results["steps"].append({
        "step": "load_database",
        "rows_affected": results["rows_processed"]
    })

    # Step 5: Cleanup
    cleanup_result = cleanup_temp_files.invoke({
        "directory": f"etl_{destination_table}",
    })
    results["steps"].append({"step": "cleanup", "result": cleanup_result})

    results["status"] = "completed"
    return results


@tool
def process_data_batch(
    query: str,
    processor_command: str,
    output_format: str = "json"
) -> Dict[str, Any]:
    """
    Process a batch of data using SQL and shell commands.

    Extracts data via SQL, processes it with a shell command,
    and returns the transformed results.

    Args:
        query: SQL query to extract data
        processor_command: Shell command to process the data
        output_format: Output format (json, csv, text)

    Returns:
        Dictionary containing processed data
    """
    # Extract data
    data = execute_sql_query.invoke({"query": query})

    # Write to temp file for processing
    import json
    import tempfile
    from pathlib import Path
    from config import file_config

    temp_path = Path(file_config.temp_dir) / "batch_input.json"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.write_text(json.dumps(data))

    # Process with shell command
    full_command = f"cat {temp_path} | {processor_command}"
    result = run_transformation_command.invoke({
        "command": full_command,
        "working_dir": file_config.temp_dir,
    })

    # Parse output
    output = result.get("stdout", "")
    if output_format == "json":
        try:
            parsed_output = json.loads(output)
        except json.JSONDecodeError:
            parsed_output = output
    else:
        parsed_output = output

    return {
        "input_rows": len(data),
        "output": parsed_output,
        "exit_code": result.get("exit_code"),
    }


@tool
def enrich_and_store_customers(
    customer_ids: List[str],
    store_results: bool = True
) -> Dict[str, Any]:
    """
    Enrich customer data and optionally store results.

    Fetches customer data, enriches it via external API,
    and stores the enriched data back to the database.

    Args:
        customer_ids: List of customer IDs to enrich
        store_results: Whether to store enriched data

    Returns:
        Dictionary containing enrichment results
    """
    from tools.database import query_customer_db

    results = {"enriched": [], "failed": [], "stored": 0}

    for customer_id in customer_ids:
        try:
            # Get current customer data
            customer = query_customer_db.invoke({"customer_id": customer_id})

            if not customer:
                results["failed"].append({
                    "customer_id": customer_id,
                    "error": "not_found"
                })
                continue

            # Call enrichment API
            enriched = call_enrichment_api.invoke({
                "customer_data": {
                    "email": customer.get("email"),
                    "domain": customer.get("domain"),
                },
                "enrichment_type": "company"
            })

            # Merge enriched data
            customer.update({
                "company_size": enriched.get("metrics", {}).get("employees"),
                "industry": enriched.get("category", {}).get("industry"),
                "enriched_at": "now()",
            })

            results["enriched"].append(customer_id)

            # Store if requested
            if store_results:
                write_to_database.invoke({
                    "table": "customers",
                    "records": [customer],
                    "operation": "upsert"
                })
                results["stored"] += 1

        except Exception as e:
            results["failed"].append({
                "customer_id": customer_id,
                "error": str(e)
            })

    return results


# Define the tools available to this agent
DATA_PIPELINE_TOOLS = [
    # Database operations
    execute_sql_query,
    write_to_database,
    # File operations
    read_csv_file,
    write_customer_document,
    # Shell operations
    run_transformation_command,
    cleanup_temp_files,
    create_processing_workspace,
    run_data_pipeline_script,
    # Enrichment
    call_enrichment_api,
    # High-level pipelines
    run_etl_pipeline,
    process_data_batch,
    enrich_and_store_customers,
]


def create_data_pipeline_agent(model_name: str = "gpt-4") -> Any:
    """
    Create the Data Pipeline Agent.

    Instantiates a ReAct agent with all data pipeline tools
    and the specified language model.

    Args:
        model_name: The OpenAI model to use

    Returns:
        Configured LangGraph agent
    """
    llm = ChatOpenAI(model=model_name, temperature=0)

    agent = create_react_agent(
        llm,
        DATA_PIPELINE_TOOLS,
        state_schema=DataPipelineState,
    )

    return agent


def get_data_pipeline_tools() -> List:
    """
    Get the list of tools for the Data Pipeline Agent.

    Returns:
        List of tool functions
    """
    return DATA_PIPELINE_TOOLS
