"""
GitOps File Operations

This module handles file operations for GitOps workflows:
- Reading and writing Kubernetes manifests
- Managing kubeconfig files
- Syncing from Git repositories

These operations modify the filesystem and can affect cluster access.
"""

import os
import subprocess
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from langchain_core.tools import tool

from config import cluster_config


MANIFESTS_DIR = Path.home() / ".gitops" / "manifests"
GIT_REPOS_DIR = Path.home() / ".gitops" / "repos"


def _ensure_dirs():
    """Ensure GitOps directories exist."""
    MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
    GIT_REPOS_DIR.mkdir(parents=True, exist_ok=True)


@tool
def read_manifest(file_path: str) -> Dict[str, Any]:
    """
    Read a Kubernetes manifest file.

    Args:
        file_path: Path to manifest file (relative to manifests dir or absolute)

    Returns:
        Manifest content and metadata
    """
    import yaml

    _ensure_dirs()

    # Resolve path
    if not Path(file_path).is_absolute():
        full_path = MANIFESTS_DIR / file_path
    else:
        full_path = Path(file_path)

    if not full_path.exists():
        return {"error": f"File not found: {full_path}"}

    content = full_path.read_text()

    # Parse YAML
    try:
        parsed = list(yaml.safe_load_all(content))
        return {
            "path": str(full_path),
            "content": content,
            "parsed": parsed,
            "document_count": len(parsed),
        }
    except yaml.YAMLError as e:
        return {
            "path": str(full_path),
            "content": content,
            "error": f"YAML parse error: {e}",
        }


@tool
def write_manifest(
    file_path: str,
    content: str,
    overwrite: bool = False
) -> Dict[str, Any]:
    """
    Write a Kubernetes manifest file.

    This saves manifest content to the local filesystem. These files
    can later be applied to the cluster or committed to GitOps repos.

    Args:
        file_path: Path for manifest file
        content: YAML content to write
        overwrite: Allow overwriting existing files

    Returns:
        Write operation result
    """
    _ensure_dirs()

    if not Path(file_path).is_absolute():
        full_path = MANIFESTS_DIR / file_path
    else:
        full_path = Path(file_path)

    if full_path.exists() and not overwrite:
        return {
            "error": "File exists",
            "path": str(full_path),
            "hint": "Set overwrite=True to replace",
        }

    # Ensure parent directory exists
    full_path.parent.mkdir(parents=True, exist_ok=True)

    full_path.write_text(content)

    return {
        "status": "written",
        "path": str(full_path),
        "size_bytes": len(content),
    }


@tool
def list_manifests(
    directory: Optional[str] = None,
    pattern: str = "*.yaml"
) -> Dict[str, Any]:
    """
    List manifest files in the manifests directory.

    Args:
        directory: Subdirectory to list (default: root manifests dir)
        pattern: Glob pattern for files

    Returns:
        List of matching files
    """
    _ensure_dirs()

    search_dir = MANIFESTS_DIR
    if directory:
        search_dir = search_dir / directory

    if not search_dir.exists():
        return {"files": [], "directory": str(search_dir)}

    files = []
    for file_path in search_dir.glob(pattern):
        if file_path.is_file():
            files.append({
                "name": file_path.name,
                "path": str(file_path),
                "size_bytes": file_path.stat().st_size,
                "modified": file_path.stat().st_mtime,
            })

    return {
        "directory": str(search_dir),
        "files": sorted(files, key=lambda f: f["name"]),
        "count": len(files),
    }


@tool
def delete_manifest(file_path: str) -> Dict[str, Any]:
    """
    Delete a manifest file.

    Args:
        file_path: Path to manifest file

    Returns:
        Deletion result
    """
    if not Path(file_path).is_absolute():
        full_path = MANIFESTS_DIR / file_path
    else:
        full_path = Path(file_path)

    if not full_path.exists():
        return {"status": "not_found", "path": str(full_path)}

    full_path.unlink()

    return {"status": "deleted", "path": str(full_path)}


@tool
def clone_gitops_repo(
    repo_url: str,
    branch: str = "main",
    target_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Clone a GitOps repository.

    This clones a Git repository containing Kubernetes manifests.
    The repo can then be used for deployments.

    Args:
        repo_url: Git repository URL
        branch: Branch to clone
        target_name: Local directory name (defaults to repo name)

    Returns:
        Clone operation result
    """
    _ensure_dirs()

    if not target_name:
        target_name = repo_url.rstrip("/").split("/")[-1]
        if target_name.endswith(".git"):
            target_name = target_name[:-4]

    target_path = GIT_REPOS_DIR / target_name

    if target_path.exists():
        return {
            "status": "exists",
            "path": str(target_path),
            "hint": "Use sync_gitops_repo to update",
        }

    result = subprocess.run(
        ["git", "clone", "--branch", branch, "--depth", "1", repo_url, str(target_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        return {
            "status": "failed",
            "error": result.stderr,
        }

    return {
        "status": "cloned",
        "path": str(target_path),
        "branch": branch,
    }


@tool
def sync_gitops_repo(repo_name: str) -> Dict[str, Any]:
    """
    Sync (pull) a GitOps repository to latest.

    Args:
        repo_name: Name of local repo directory

    Returns:
        Sync operation result
    """
    repo_path = GIT_REPOS_DIR / repo_name

    if not repo_path.exists():
        return {"error": f"Repository not found: {repo_name}"}

    result = subprocess.run(
        ["git", "pull", "--rebase"],
        capture_output=True,
        text=True,
        cwd=str(repo_path),
        timeout=60,
    )

    return {
        "status": "synced" if result.returncode == 0 else "failed",
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


@tool
def update_kubeconfig(
    cluster_name: str,
    api_server: str,
    certificate_authority: str,
    client_certificate: Optional[str] = None,
    client_key: Optional[str] = None,
    token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Add or update a cluster in kubeconfig.

    This modifies the kubeconfig file to add cluster credentials.
    Changes here affect what clusters can be accessed.

    Args:
        cluster_name: Name for the cluster entry
        api_server: Kubernetes API server URL
        certificate_authority: CA certificate data (base64)
        client_certificate: Client cert for auth (base64)
        client_key: Client key for auth (base64)
        token: Bearer token for auth (alternative to certs)

    Returns:
        Update result
    """
    # Set cluster
    result = subprocess.run(
        [
            "kubectl", "config", "set-cluster", cluster_name,
            f"--server={api_server}",
            f"--certificate-authority-data={certificate_authority}",
            "--embed-certs=true"
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return {"error": "Failed to set cluster", "stderr": result.stderr}

    # Set credentials
    cred_name = f"{cluster_name}-user"
    cred_cmd = ["kubectl", "config", "set-credentials", cred_name]

    if token:
        cred_cmd.append(f"--token={token}")
    elif client_certificate and client_key:
        cred_cmd.extend([
            f"--client-certificate-data={client_certificate}",
            f"--client-key-data={client_key}",
            "--embed-certs=true"
        ])

    result = subprocess.run(cred_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return {"error": "Failed to set credentials", "stderr": result.stderr}

    # Set context
    context_name = f"{cluster_name}-context"
    result = subprocess.run(
        [
            "kubectl", "config", "set-context", context_name,
            f"--cluster={cluster_name}",
            f"--user={cred_name}"
        ],
        capture_output=True,
        text=True,
    )

    return {
        "status": "configured",
        "cluster": cluster_name,
        "context": context_name,
        "kubeconfig": cluster_config.kubeconfig_path,
    }


@tool
def backup_kubeconfig() -> Dict[str, Any]:
    """
    Create a backup of the current kubeconfig.

    Returns:
        Backup file path and status
    """
    import datetime

    kubeconfig = Path(cluster_config.kubeconfig_path)

    if not kubeconfig.exists():
        return {"error": "No kubeconfig to backup"}

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = kubeconfig.parent / f"config.backup.{timestamp}"

    shutil.copy2(kubeconfig, backup_path)

    return {
        "status": "backed_up",
        "original": str(kubeconfig),
        "backup": str(backup_path),
    }


@tool
def clean_old_repos(days_old: int = 30) -> Dict[str, Any]:
    """
    Clean up old GitOps repository clones.

    Removes repo directories that haven't been modified recently.

    Args:
        days_old: Remove repos not modified in this many days

    Returns:
        Cleanup results
    """
    import time

    _ensure_dirs()

    current_time = time.time()
    cutoff_seconds = days_old * 24 * 60 * 60
    removed = []

    for repo_dir in GIT_REPOS_DIR.iterdir():
        if repo_dir.is_dir():
            mtime = repo_dir.stat().st_mtime
            if current_time - mtime > cutoff_seconds:
                shutil.rmtree(repo_dir)
                removed.append(str(repo_dir))

    return {
        "status": "cleaned",
        "removed_count": len(removed),
        "removed": removed,
    }
