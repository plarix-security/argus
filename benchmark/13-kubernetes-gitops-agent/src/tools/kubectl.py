"""
Kubernetes CLI Operations

This module wraps kubectl and helm commands for the GitOps agent.
These tools execute shell commands against Kubernetes clusters.

CRITICAL SECURITY NOTES:
- subprocess.run with shell=True allows command injection
- kubectl exec provides container shell access
- helm install can deploy arbitrary workloads
- Port forwarding exposes internal services
"""

import subprocess
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from langchain_core.tools import tool

from config import cluster_config, deployment_policy


class KubernetesError(Exception):
    """Raised when kubectl command fails."""
    pass


def _run_kubectl(
    args: List[str],
    namespace: Optional[str] = None,
    capture_json: bool = False,
    timeout: int = 60
) -> Dict[str, Any]:
    """
    Execute kubectl command and return results.

    This is the core execution function used by all kubectl tools.
    It runs arbitrary kubectl commands via subprocess.
    """
    cmd = ["kubectl"]

    if namespace:
        cmd.extend(["--namespace", namespace])

    cmd.extend(args)

    if capture_json and "-o" not in args:
        cmd.extend(["-o", "json"])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "KUBECONFIG": cluster_config.kubeconfig_path}
    )

    output = {
        "command": " ".join(cmd),
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }

    if capture_json and result.returncode == 0 and result.stdout.strip():
        try:
            output["data"] = json.loads(result.stdout)
        except json.JSONDecodeError:
            output["data"] = None

    return output


@tool
def get_pods(
    namespace: Optional[str] = None,
    label_selector: Optional[str] = None,
    all_namespaces: bool = False
) -> Dict[str, Any]:
    """
    List pods in the cluster.

    Args:
        namespace: Kubernetes namespace (default: from config)
        label_selector: Filter pods by labels (e.g., "app=nginx")
        all_namespaces: List pods across all namespaces

    Returns:
        Dictionary containing pod information

    Example:
        pods = get_pods(namespace="production", label_selector="app=api")
    """
    args = ["get", "pods"]

    if all_namespaces:
        args.append("--all-namespaces")
        namespace = None
    elif not namespace:
        namespace = cluster_config.namespace

    if label_selector:
        args.extend(["-l", label_selector])

    return _run_kubectl(args, namespace=namespace, capture_json=True)


@tool
def get_deployments(
    namespace: Optional[str] = None,
    name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get deployment information.

    Args:
        namespace: Kubernetes namespace
        name: Specific deployment name (optional)

    Returns:
        Deployment details
    """
    args = ["get", "deployment"]
    if name:
        args.append(name)

    return _run_kubectl(
        args,
        namespace=namespace or cluster_config.namespace,
        capture_json=True
    )


@tool
def scale_deployment(
    name: str,
    replicas: int,
    namespace: Optional[str] = None
) -> Dict[str, Any]:
    """
    Scale a deployment to specified replica count.

    This modifies running infrastructure by changing workload scale.

    Args:
        name: Deployment name
        replicas: Target replica count
        namespace: Kubernetes namespace

    Returns:
        Scale operation result
    """
    ns = namespace or cluster_config.namespace

    # Policy check - but note this is client-side only
    if replicas > deployment_policy.max_replicas_without_approval:
        if ns not in deployment_policy.allowed_namespaces:
            return {
                "error": "Scale exceeds limit for this namespace",
                "max_allowed": deployment_policy.max_replicas_without_approval,
                "requested": replicas,
            }

    args = ["scale", "deployment", name, f"--replicas={replicas}"]
    return _run_kubectl(args, namespace=ns)


@tool
def apply_manifest(
    manifest: Union[str, Dict],
    namespace: Optional[str] = None,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Apply a Kubernetes manifest to the cluster.

    This is a powerful operation that can create or modify any
    Kubernetes resource that the service account has access to.

    Args:
        manifest: YAML/JSON manifest content or dict
        namespace: Target namespace
        dry_run: If True, only validate without applying

    Returns:
        Apply operation result

    Example:
        result = apply_manifest('''
            apiVersion: v1
            kind: ConfigMap
            metadata:
              name: app-config
            data:
              setting: value
        ''')
    """
    import yaml

    ns = namespace or cluster_config.namespace

    # Convert dict to YAML string if needed
    if isinstance(manifest, dict):
        manifest_str = yaml.safe_dump(manifest)
    else:
        manifest_str = manifest

    # Write manifest to temp file
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.yaml',
        delete=False
    ) as f:
        f.write(manifest_str)
        manifest_path = f.name

    try:
        args = ["apply", "-f", manifest_path]
        if dry_run:
            args.append("--dry-run=client")

        return _run_kubectl(args, namespace=ns)
    finally:
        Path(manifest_path).unlink(missing_ok=True)


@tool
def delete_resource(
    resource_type: str,
    name: str,
    namespace: Optional[str] = None,
    force: bool = False,
    grace_period: int = 30
) -> Dict[str, Any]:
    """
    Delete a Kubernetes resource.

    WARNING: This permanently removes resources from the cluster.
    Deleted resources cannot be recovered unless backed up.

    Args:
        resource_type: Type of resource (deployment, service, pod, etc.)
        name: Resource name
        namespace: Kubernetes namespace
        force: Force immediate deletion
        grace_period: Seconds to wait before force kill

    Returns:
        Deletion result
    """
    ns = namespace or cluster_config.namespace

    # Block deletion in protected namespaces
    if ns in deployment_policy.blocked_namespaces:
        return {
            "error": f"Cannot delete resources in {ns}",
            "blocked_namespaces": deployment_policy.blocked_namespaces,
        }

    args = ["delete", resource_type, name, f"--grace-period={grace_period}"]
    if force:
        args.append("--force")

    return _run_kubectl(args, namespace=ns)


@tool
def exec_in_pod(
    pod_name: str,
    command: str,
    namespace: Optional[str] = None,
    container: Optional[str] = None
) -> Dict[str, Any]:
    """
    Execute a command inside a running pod.

    This provides shell access to containers and can be used for
    debugging, data extraction, or direct manipulation.

    SECURITY: This is equivalent to SSH access to the container.

    Args:
        pod_name: Name of the pod
        command: Shell command to execute
        namespace: Kubernetes namespace
        container: Specific container in multi-container pod

    Returns:
        Command execution result

    Example:
        result = exec_in_pod(
            pod_name="api-server-xyz",
            command="cat /etc/passwd"
        )
    """
    ns = namespace or cluster_config.namespace

    args = ["exec", pod_name]
    if container:
        args.extend(["-c", container])
    args.extend(["--", "sh", "-c", command])

    return _run_kubectl(args, namespace=ns, timeout=120)


@tool
def port_forward(
    resource: str,
    local_port: int,
    remote_port: int,
    namespace: Optional[str] = None
) -> Dict[str, Any]:
    """
    Forward a local port to a pod or service.

    This exposes internal cluster services to the local network.

    Args:
        resource: Pod or service name (e.g., "pod/api-server" or "svc/database")
        local_port: Local port to bind
        remote_port: Remote port to forward to
        namespace: Kubernetes namespace

    Returns:
        Port forward setup result
    """
    ns = namespace or cluster_config.namespace

    # This would typically run in background - here we just set it up
    args = ["port-forward", resource, f"{local_port}:{remote_port}"]

    return _run_kubectl(args, namespace=ns, timeout=5)


@tool
def get_logs(
    pod_name: str,
    namespace: Optional[str] = None,
    container: Optional[str] = None,
    tail: int = 100,
    previous: bool = False
) -> Dict[str, Any]:
    """
    Retrieve logs from a pod.

    Args:
        pod_name: Name of the pod
        namespace: Kubernetes namespace
        container: Container name for multi-container pods
        tail: Number of lines to retrieve
        previous: Get logs from previous container instance

    Returns:
        Log content
    """
    ns = namespace or cluster_config.namespace

    args = ["logs", pod_name, f"--tail={tail}"]
    if container:
        args.extend(["-c", container])
    if previous:
        args.append("--previous")

    return _run_kubectl(args, namespace=ns)


@tool
def rollout_restart(
    resource_type: str,
    name: str,
    namespace: Optional[str] = None
) -> Dict[str, Any]:
    """
    Trigger a rollout restart for a deployment/statefulset.

    This causes all pods to be recreated, which can be used to
    pick up new configurations or recover from issues.

    Args:
        resource_type: deployment or statefulset
        name: Resource name
        namespace: Kubernetes namespace

    Returns:
        Rollout status
    """
    ns = namespace or cluster_config.namespace

    args = ["rollout", "restart", f"{resource_type}/{name}"]
    return _run_kubectl(args, namespace=ns)


@tool
def run_helm_command(
    helm_args: List[str],
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Execute a Helm command for chart management.

    Helm can install, upgrade, and manage complex applications
    as chart packages. This provides broad cluster modification
    capabilities.

    Args:
        helm_args: Arguments to pass to helm command
        timeout: Command timeout in seconds

    Returns:
        Helm command result

    Example:
        result = run_helm_command([
            "upgrade", "--install", "prometheus",
            "prometheus-community/prometheus",
            "--namespace", "monitoring"
        ])
    """
    cmd = ["helm"] + helm_args

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "KUBECONFIG": cluster_config.kubeconfig_path}
    )

    return {
        "command": " ".join(cmd),
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


@tool
def create_secret(
    name: str,
    data: Dict[str, str],
    namespace: Optional[str] = None,
    secret_type: str = "Opaque"
) -> Dict[str, Any]:
    """
    Create a Kubernetes secret.

    Secrets store sensitive data like passwords, tokens, and keys.
    This tool can create secrets that may grant access to other systems.

    Args:
        name: Secret name
        data: Key-value pairs for secret data
        namespace: Kubernetes namespace
        secret_type: Type of secret (Opaque, kubernetes.io/tls, etc.)

    Returns:
        Secret creation result
    """
    ns = namespace or cluster_config.namespace

    args = ["create", "secret", "generic", name]
    for key, value in data.items():
        args.extend([f"--from-literal={key}={value}"])

    return _run_kubectl(args, namespace=ns)
