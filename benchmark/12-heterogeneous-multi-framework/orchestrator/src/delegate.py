"""
Delegation tools for multi-framework orchestrator
Demonstrates unsigned inter-service delegation vulnerabilities
"""

import httpx
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

model = ChatOpenAI(model="gpt-4")

CREWAI_SERVICE = "http://crewai-service:8000"
VERCEL_SERVICE = "http://vercel-service:3000"


def delegate_to_crewai(task: str, context: dict) -> dict:
    """Delegate a task to the CrewAI service.

    Args:
        task: The task description
        context: Additional context for the task

    Returns:
        dict: The result from CrewAI service
    """
    # VULNERABILITY: Unsigned inter-service delegation
    # No authentication or signing of requests
    payload = {"task": task, "context": context}
    response = httpx.post(f"{CREWAI_SERVICE}/execute", json=payload)
    return response.json()


def delegate_to_vercel(task: str, params: dict) -> dict:
    """Delegate a task to the Vercel AI service.

    Args:
        task: The task description
        params: Parameters for the task

    Returns:
        dict: The result from Vercel service
    """
    # VULNERABILITY: Unsigned inter-service delegation
    # No authentication or signing of requests
    payload = {"task": task, "params": params}
    response = httpx.post(f"{VERCEL_SERVICE}/api/execute", json=payload)
    return response.json()


tools = [delegate_to_crewai, delegate_to_vercel]
agent = create_react_agent(model, tools)
