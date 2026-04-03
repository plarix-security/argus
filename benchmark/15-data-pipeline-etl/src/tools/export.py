"""
Data Export Tools

This module provides data export capabilities for the ETL agent.
Supports exporting to various file formats.

SECURITY NOTES:
- File writes to user-specified paths
- No path sanitization
- Large data can fill disk
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from langchain_core.tools import tool

from config import storage_config


def _resolve_export_path(filename: str) -> Path:
    """Resolve export file path."""
    if Path(filename).is_absolute():
        return Path(filename)
    return storage_config.export_dir / filename


@tool
def export_to_csv(
    data: List[Dict[str, Any]],
    filename: str,
    overwrite: bool = False
) -> Dict[str, Any]:
    """
    Export data to a CSV file.

    Args:
        data: List of row dictionaries
        filename: Output filename
        overwrite: Allow overwriting existing files

    Returns:
        Export result

    Example:
        result = export_to_csv(
            data=[{"name": "Alice", "age": 30}],
            filename="users.csv"
        )
    """
    if not data:
        return {"error": "No data to export"}

    path = _resolve_export_path(filename)

    if path.exists() and not overwrite:
        return {
            "error": "File exists",
            "path": str(path),
            "hint": "Set overwrite=True to replace"
        }

    path.parent.mkdir(parents=True, exist_ok=True)

    columns = list(data[0].keys())

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(data)

    return {
        "success": True,
        "path": str(path),
        "rows": len(data),
        "columns": columns,
    }


@tool
def export_to_json(
    data: Any,
    filename: str,
    indent: int = 2,
    overwrite: bool = False
) -> Dict[str, Any]:
    """
    Export data to a JSON file.

    Args:
        data: Data to export
        filename: Output filename
        indent: JSON indentation
        overwrite: Allow overwriting

    Returns:
        Export result
    """
    path = _resolve_export_path(filename)

    if path.exists() and not overwrite:
        return {"error": "File exists", "path": str(path)}

    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, default=str)

    return {
        "success": True,
        "path": str(path),
        "size_bytes": path.stat().st_size,
    }


@tool
def export_to_parquet(
    data: List[Dict[str, Any]],
    filename: str,
    overwrite: bool = False
) -> Dict[str, Any]:
    """
    Export data to Parquet format.

    Parquet is a columnar format efficient for analytics.

    Args:
        data: List of row dictionaries
        filename: Output filename
        overwrite: Allow overwriting

    Returns:
        Export result
    """
    try:
        import pandas as pd
    except ImportError:
        return {"error": "pandas not installed"}

    path = _resolve_export_path(filename)

    if path.exists() and not overwrite:
        return {"error": "File exists", "path": str(path)}

    path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(data)
    df.to_parquet(path, index=False)

    return {
        "success": True,
        "path": str(path),
        "rows": len(data),
        "columns": list(df.columns),
    }


@tool
def list_exports(pattern: str = "*") -> Dict[str, Any]:
    """
    List exported files.

    Args:
        pattern: Glob pattern

    Returns:
        List of export files
    """
    export_dir = storage_config.export_dir
    export_dir.mkdir(parents=True, exist_ok=True)

    files = []
    for path in export_dir.glob(pattern):
        if path.is_file():
            files.append({
                "name": path.name,
                "path": str(path),
                "size_bytes": path.stat().st_size,
                "modified": path.stat().st_mtime,
            })

    return {
        "directory": str(export_dir),
        "files": sorted(files, key=lambda f: f["name"]),
        "count": len(files),
    }


@tool
def delete_export(filename: str) -> Dict[str, Any]:
    """
    Delete an exported file.

    Args:
        filename: File to delete

    Returns:
        Deletion result
    """
    path = _resolve_export_path(filename)

    if not path.exists():
        return {"status": "not_found", "path": str(path)}

    path.unlink()

    return {"status": "deleted", "path": str(path)}


@tool
def read_export(filename: str) -> Dict[str, Any]:
    """
    Read an exported file.

    Args:
        filename: File to read

    Returns:
        File contents
    """
    path = _resolve_export_path(filename)

    if not path.exists():
        return {"error": "File not found", "path": str(path)}

    suffix = path.suffix.lower()

    if suffix == ".csv":
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            data = list(reader)
        return {"data": data, "format": "csv", "rows": len(data)}

    elif suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {"data": data, "format": "json"}

    elif suffix == ".parquet":
        try:
            import pandas as pd
            df = pd.read_parquet(path)
            return {
                "data": df.to_dict(orient="records"),
                "format": "parquet",
                "rows": len(df),
            }
        except ImportError:
            return {"error": "pandas not installed"}

    else:
        content = path.read_text()
        return {"data": content, "format": "text"}
