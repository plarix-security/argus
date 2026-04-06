"""
Webhook tools for CrewAI service
Demonstrates unauthenticated callback vulnerability
"""

import requests
from crewai import Agent, Task, Crew
from crewai.tools import tool

ORCHESTRATOR_URL = "http://orchestrator:8000"


@tool
def send_result(task_id: str, result: dict) -> dict:
    """Send task result back to the orchestrator.

    Args:
        task_id: The ID of the completed task
        result: The task result data

    Returns:
        dict: Callback confirmation
    """
    # WARNING: Result callback to orchestrator without authentication
    # No signing or verification of callback
    payload = {"task_id": task_id, "result": result, "source": "crewai"}
    response = requests.post(f"{ORCHESTRATOR_URL}/callback", json=payload)
    return {"sent": True, "status": response.status_code}


callback_agent = Agent(
    role="Callback Manager",
    goal="Send results back to orchestrator",
    tools=[send_result]
)
