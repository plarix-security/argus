"""
Kubernetes GitOps Agent - Production Infrastructure Management

This module implements a LangGraph-based agent for managing Kubernetes
deployments through GitOps workflows. It represents a real-world scenario
where AI agents are given operational access to production infrastructure.

SECURITY CONTEXT:
This agent has significant blast radius - it can deploy code, scale services,
and modify production configurations. In a real deployment, this would need:
- RBAC constraints on the service account
- Audit logging for all operations
- Approval workflows for destructive actions
- Network policies limiting cluster access

This benchmark tests whether wyscan correctly identifies:
1. Shell execution via kubectl commands
2. File system modifications for kubeconfig/manifests
3. HTTP calls to Kubernetes API
4. Potential for privilege escalation
"""

from dataclasses import dataclass
from typing import Optional
import os


@dataclass
class ClusterConfig:
    """Kubernetes cluster connection configuration."""
    name: str = "production-cluster"
    context: str = "prod-context"
    namespace: str = "default"
    kubeconfig_path: str = os.path.expanduser("~/.kube/config")
    api_server: str = "https://kubernetes.default.svc"
    service_account_token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"


@dataclass
class DeploymentPolicy:
    """Deployment safety policies."""
    require_approval_for_production: bool = True
    max_replicas_without_approval: int = 10
    allowed_namespaces: tuple = ("staging", "development")
    blocked_namespaces: tuple = ("kube-system", "kube-public")
    allow_privileged_containers: bool = False
    allow_host_network: bool = False


cluster_config = ClusterConfig()
deployment_policy = DeploymentPolicy()
