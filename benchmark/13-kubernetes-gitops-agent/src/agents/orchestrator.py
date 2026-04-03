"""
Kubernetes GitOps Agent Orchestrator

This module implements the LangGraph agent that orchestrates Kubernetes
deployments through GitOps workflows. It demonstrates a sophisticated
multi-tool agent with significant infrastructure access.

ARCHITECTURE:
The agent uses a ReAct pattern with tool calling to:
1. Analyze deployment requests
2. Fetch manifest changes from Git
3. Apply changes to Kubernetes
4. Monitor rollout status

This is a realistic production scenario where the agent has autonomy
over infrastructure changes within defined guardrails.
"""

from typing import Any, Dict, List, Literal, TypedDict, Annotated
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from tools.kubectl import (
    get_pods,
    get_deployments,
    scale_deployment,
    apply_manifest,
    delete_resource,
    exec_in_pod,
    port_forward,
    get_logs,
    rollout_restart,
    run_helm_command,
    create_secret,
)
from tools.gitops import (
    read_manifest,
    write_manifest,
    list_manifests,
    delete_manifest,
    clone_gitops_repo,
    sync_gitops_repo,
    update_kubeconfig,
    backup_kubeconfig,
    clean_old_repos,
)


# All available tools for the agent
TOOLS = [
    # Kubectl operations
    get_pods,
    get_deployments,
    scale_deployment,
    apply_manifest,
    delete_resource,
    exec_in_pod,
    port_forward,
    get_logs,
    rollout_restart,
    run_helm_command,
    create_secret,
    # GitOps operations
    read_manifest,
    write_manifest,
    list_manifests,
    delete_manifest,
    clone_gitops_repo,
    sync_gitops_repo,
    update_kubeconfig,
    backup_kubeconfig,
    clean_old_repos,
]


class AgentState(TypedDict):
    """State maintained across agent steps."""
    messages: List[Any]
    current_task: str
    cluster_context: Dict[str, Any]
    pending_changes: List[Dict[str, Any]]
    applied_changes: List[Dict[str, Any]]
    errors: List[str]


SYSTEM_PROMPT = """You are a Kubernetes GitOps automation agent. Your role is to help manage Kubernetes deployments through GitOps workflows.

Capabilities:
- View and manage Kubernetes resources (pods, deployments, services)
- Apply and manage YAML manifests
- Execute commands in pods for debugging
- Manage Helm releases
- Sync with Git repositories for GitOps workflows

Safety guidelines:
- Always verify the target namespace before making changes
- Use dry-run when possible before actual apply
- Get approval before deleting resources in production
- Create backups before major configuration changes

When asked to deploy or update, follow this workflow:
1. Check current state of the resource
2. Review the manifest changes
3. Apply with dry-run to validate
4. Apply the actual changes
5. Monitor the rollout status
"""


def create_agent_graph():
    """
    Create the LangGraph agent graph for Kubernetes operations.

    Returns:
        Compiled graph ready for execution
    """
    tool_node = ToolNode(TOOLS)

    def should_continue(state: AgentState) -> Literal["tools", "end"]:
        """Determine if we should continue tool calling."""
        messages = state.get("messages", [])
        if not messages:
            return "end"

        last_message = messages[-1]
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
        return "end"

    def agent_step(state: AgentState) -> Dict[str, Any]:
        """Execute one step of the agent."""
        # This would normally call an LLM - here we just pass through
        # for testing the tool availability analysis
        return state

    # Build graph
    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_step)
    graph.add_node("tools", tool_node)

    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue)
    graph.add_edge("tools", "agent")

    return graph.compile()


def run_deployment_workflow(
    manifest_path: str,
    namespace: str,
    dry_run: bool = True
) -> Dict[str, Any]:
    """
    Execute a deployment workflow.

    This is a common operation pattern that:
    1. Reads the manifest
    2. Validates it with dry-run
    3. Applies if valid
    4. Monitors rollout

    Args:
        manifest_path: Path to Kubernetes manifest
        namespace: Target namespace
        dry_run: If True, only validate without applying

    Returns:
        Workflow result summary
    """
    results = {
        "steps": [],
        "success": False,
        "manifest_path": manifest_path,
        "namespace": namespace,
    }

    # Step 1: Read manifest
    manifest_result = read_manifest.invoke({"file_path": manifest_path})
    results["steps"].append({"action": "read_manifest", "result": manifest_result})

    if "error" in manifest_result:
        results["error"] = manifest_result["error"]
        return results

    # Step 2: Check current state
    deployments_result = get_deployments.invoke({"namespace": namespace})
    results["steps"].append({"action": "get_deployments", "result": deployments_result})

    # Step 3: Apply with validation
    apply_result = apply_manifest.invoke({
        "manifest": manifest_result["content"],
        "namespace": namespace,
        "dry_run": dry_run,
    })
    results["steps"].append({
        "action": "apply_manifest",
        "dry_run": dry_run,
        "result": apply_result
    })

    if apply_result.get("exit_code") == 0:
        results["success"] = True

    return results


def emergency_rollback(
    deployment_name: str,
    namespace: str
) -> Dict[str, Any]:
    """
    Execute emergency rollback for a failed deployment.

    This is a recovery operation that:
    1. Gets current deployment status
    2. Rolls back to previous revision
    3. Monitors rollout

    Args:
        deployment_name: Name of deployment to rollback
        namespace: Kubernetes namespace

    Returns:
        Rollback result
    """
    from tools.kubectl import _run_kubectl

    # Execute rollback
    result = _run_kubectl(
        ["rollout", "undo", f"deployment/{deployment_name}"],
        namespace=namespace
    )

    return {
        "action": "emergency_rollback",
        "deployment": deployment_name,
        "namespace": namespace,
        "result": result,
    }


# Agent instance
agent = create_agent_graph()
