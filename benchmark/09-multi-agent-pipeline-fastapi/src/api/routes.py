"""
FastAPI Routes for Multi-Agent Pipeline

API endpoints for agent management and configuration.
Demonstrates AFB04 vulnerabilities in path traversal.
"""

from pathlib import Path
from typing import Any, Dict
from fastapi import APIRouter, HTTPException
from langchain_core.tools import tool

router = APIRouter()


@tool
def load_agent_config(agent_id: str) -> Dict[str, Any]:
    """
    Load agent configuration from file.

    AFB04 WARNING: Path traversal vulnerability.
    Agent ID is used directly in file path construction.

    Args:
        agent_id: Agent identifier (vulnerable to traversal)
    """
    # No sanitization of agent_id
    config_path = Path("./configs") / f"{agent_id}.json"
    #
    #
    content = config_path.read_text()
    return {"config": content, "agent_id": agent_id}


@router.get("/agents/{agent_id}/config")
async def get_agent_config(agent_id: str):
    """API endpoint for agent configuration."""
    try:
        result = load_agent_config(agent_id)
        return result
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Agent not found")


# Export tools
API_TOOLS = [load_agent_config]
