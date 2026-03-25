"""
Orchestrator for the Customer Operations Platform.

This module implements the main LangGraph StateGraph that coordinates
between the Customer Operations Agent and Data Pipeline Agent,
routing tasks and maintaining shared state.
"""

from typing import Any, Annotated, Dict, List, Literal, TypedDict, Sequence
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

from agents.customer_ops_agent import (
    create_customer_ops_agent,
    get_customer_ops_tools,
    CUSTOMER_OPS_TOOLS,
)
from agents.data_pipeline_agent import (
    create_data_pipeline_agent,
    get_data_pipeline_tools,
    DATA_PIPELINE_TOOLS,
)


class OrchestratorState(TypedDict):
    """
    Shared state schema for the orchestrator.

    This state is passed between all nodes in the graph and maintains
    context across agent invocations.
    """

    messages: Annotated[Sequence[BaseMessage], add_messages]
    current_agent: str
    task_type: str
    customer_id: str | None
    job_context: Dict[str, Any]
    completed_steps: List[str]
    error: str | None


def classify_task(state: OrchestratorState) -> OrchestratorState:
    """
    Classify the incoming task and determine routing.

    Analyzes the user message to determine whether to route to
    Customer Operations or Data Pipeline agent.

    Args:
        state: Current orchestrator state

    Returns:
        Updated state with task classification
    """
    messages = state.get("messages", [])
    if not messages:
        return {**state, "task_type": "unknown", "error": "No messages provided"}

    last_message = messages[-1]
    content = last_message.content.lower() if hasattr(last_message, 'content') else str(last_message).lower()

    # Keywords for customer operations
    customer_keywords = [
        "customer", "ticket", "support", "email", "crm",
        "contact", "document", "request", "help", "issue"
    ]

    # Keywords for data pipeline
    pipeline_keywords = [
        "data", "pipeline", "etl", "csv", "sql", "query",
        "transform", "process", "batch", "enrich", "export"
    ]

    customer_score = sum(1 for kw in customer_keywords if kw in content)
    pipeline_score = sum(1 for kw in pipeline_keywords if kw in content)

    if customer_score > pipeline_score:
        task_type = "customer_ops"
    elif pipeline_score > customer_score:
        task_type = "data_pipeline"
    else:
        # Default to customer ops for ambiguous requests
        task_type = "customer_ops"

    return {
        **state,
        "task_type": task_type,
        "current_agent": task_type,
    }


def route_to_agent(state: OrchestratorState) -> Literal["customer_ops", "data_pipeline", "end"]:
    """
    Determine which agent node to route to.

    Args:
        state: Current orchestrator state

    Returns:
        Name of the next node to execute
    """
    task_type = state.get("task_type", "")

    if task_type == "customer_ops":
        return "customer_ops"
    elif task_type == "data_pipeline":
        return "data_pipeline"
    else:
        return "end"


def customer_ops_node(state: OrchestratorState) -> OrchestratorState:
    """
    Execute the Customer Operations Agent.

    Invokes the customer operations agent with the current state
    and available tools.

    Args:
        state: Current orchestrator state

    Returns:
        Updated state with agent results
    """
    agent = create_customer_ops_agent()

    # Prepare agent input
    agent_input = {
        "messages": state.get("messages", []),
    }

    if state.get("customer_id"):
        agent_input["customer_id"] = state["customer_id"]

    # Execute agent
    result = agent.invoke(agent_input)

    # Update state with results
    completed = list(state.get("completed_steps", []))
    completed.append("customer_ops")

    return {
        **state,
        "messages": result.get("messages", state.get("messages", [])),
        "completed_steps": completed,
        "job_context": {
            **state.get("job_context", {}),
            "customer_ops_result": result,
        }
    }


def data_pipeline_node(state: OrchestratorState) -> OrchestratorState:
    """
    Execute the Data Pipeline Agent.

    Invokes the data pipeline agent with the current state
    and available tools.

    Args:
        state: Current orchestrator state

    Returns:
        Updated state with agent results
    """
    agent = create_data_pipeline_agent()

    # Prepare agent input
    agent_input = {
        "messages": state.get("messages", []),
    }

    # Execute agent
    result = agent.invoke(agent_input)

    # Update state with results
    completed = list(state.get("completed_steps", []))
    completed.append("data_pipeline")

    return {
        **state,
        "messages": result.get("messages", state.get("messages", [])),
        "completed_steps": completed,
        "job_context": {
            **state.get("job_context", {}),
            "data_pipeline_result": result,
        }
    }


def should_continue(state: OrchestratorState) -> Literal["continue", "end"]:
    """
    Determine whether to continue processing or end.

    Checks if additional processing steps are needed based on
    the agent's response.

    Args:
        state: Current orchestrator state

    Returns:
        "continue" or "end"
    """
    messages = state.get("messages", [])
    if not messages:
        return "end"

    last_message = messages[-1]

    # Check if the agent is requesting additional work
    content = last_message.content if hasattr(last_message, 'content') else str(last_message)

    continuation_signals = [
        "need to also",
        "additionally",
        "next step",
        "processing data",
        "will now",
    ]

    for signal in continuation_signals:
        if signal in content.lower():
            # Swap agents for cross-functional work
            current = state.get("current_agent", "")
            if current == "customer_ops":
                return "continue"
            elif current == "data_pipeline":
                return "continue"

    return "end"


def handoff_node(state: OrchestratorState) -> OrchestratorState:
    """
    Handle handoff between agents.

    Prepares state for transitioning from one agent to another
    when cross-functional work is needed.

    Args:
        state: Current orchestrator state

    Returns:
        Updated state for agent handoff
    """
    current = state.get("current_agent", "")

    # Swap to the other agent
    if current == "customer_ops":
        new_agent = "data_pipeline"
        new_task_type = "data_pipeline"
    else:
        new_agent = "customer_ops"
        new_task_type = "customer_ops"

    return {
        **state,
        "current_agent": new_agent,
        "task_type": new_task_type,
    }


def create_orchestrator() -> StateGraph:
    """
    Create the main orchestrator graph.

    Builds a LangGraph StateGraph that coordinates between
    the Customer Operations and Data Pipeline agents.

    Returns:
        Compiled StateGraph ready for execution
    """
    # Create the graph
    workflow = StateGraph(OrchestratorState)

    # Add nodes
    workflow.add_node("classify", classify_task)
    workflow.add_node("customer_ops", customer_ops_node)
    workflow.add_node("data_pipeline", data_pipeline_node)
    workflow.add_node("handoff", handoff_node)

    # Set entry point
    workflow.set_entry_point("classify")

    # Add edges from classify
    workflow.add_conditional_edges(
        "classify",
        route_to_agent,
        {
            "customer_ops": "customer_ops",
            "data_pipeline": "data_pipeline",
            "end": END,
        }
    )

    # Add edges from customer_ops
    workflow.add_conditional_edges(
        "customer_ops",
        should_continue,
        {
            "continue": "handoff",
            "end": END,
        }
    )

    # Add edges from data_pipeline
    workflow.add_conditional_edges(
        "data_pipeline",
        should_continue,
        {
            "continue": "handoff",
            "end": END,
        }
    )

    # Add edges from handoff back to agents
    workflow.add_conditional_edges(
        "handoff",
        route_to_agent,
        {
            "customer_ops": "customer_ops",
            "data_pipeline": "data_pipeline",
            "end": END,
        }
    )

    # Compile the graph
    return workflow.compile()


def run_orchestrator(user_message: str, customer_id: str | None = None) -> Dict[str, Any]:
    """
    Run the orchestrator with a user message.

    Main entry point for executing workflows through the orchestrator.

    Args:
        user_message: The user's request
        customer_id: Optional customer ID for context

    Returns:
        Dictionary containing execution results

    Example:
        result = run_orchestrator(
            "Create a support ticket for customer CUST-123 about billing issues",
            customer_id="CUST-123"
        )
    """
    orchestrator = create_orchestrator()

    initial_state: OrchestratorState = {
        "messages": [HumanMessage(content=user_message)],
        "current_agent": "",
        "task_type": "",
        "customer_id": customer_id,
        "job_context": {},
        "completed_steps": [],
        "error": None,
    }

    final_state = orchestrator.invoke(initial_state)

    return {
        "messages": final_state.get("messages", []),
        "completed_steps": final_state.get("completed_steps", []),
        "job_context": final_state.get("job_context", {}),
    }


# Export all tools for external access
ALL_TOOLS = CUSTOMER_OPS_TOOLS + DATA_PIPELINE_TOOLS


if __name__ == "__main__":
    # Example usage
    result = run_orchestrator(
        "Look up customer CUST-456 and create a support ticket for their billing inquiry"
    )
    print(result)
