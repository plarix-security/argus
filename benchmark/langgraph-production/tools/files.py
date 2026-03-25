"""
File operations for the Customer Operations Platform.

This module provides tools for reading and writing files, including
customer documents and CSV data files.
"""

import os
import csv
from pathlib import Path
from typing import Any, Dict, List, Optional
from langchain_core.tools import tool

from config import file_config


@tool
def read_customer_document(
    document_path: str,
    encoding: str = "utf-8"
) -> Dict[str, Any]:
    """
    Read a customer document from the file system.

    Reads document content from the configured documents directory.
    This tool accesses the file system for read operations.

    Args:
        document_path: Relative path to the document within documents dir
        encoding: File encoding (default: utf-8)

    Returns:
        Dictionary containing document content and metadata

    Example:
        doc = read_customer_document("contracts/cust_123_agreement.txt")
    """
    full_path = Path(file_config.documents_dir) / document_path

    if not full_path.exists():
        return {"error": "Document not found", "path": str(full_path)}

    content = full_path.read_text(encoding=encoding)
    stat = full_path.stat()

    return {
        "path": str(full_path),
        "content": content,
        "size_bytes": stat.st_size,
        "modified_at": stat.st_mtime,
    }


@tool
def write_customer_document(
    document_path: str,
    content: str,
    overwrite: bool = False
) -> Dict[str, Any]:
    """
    Write a document to the customer documents directory.

    Creates or updates a document file in the file system.
    This tool performs file write operations.

    Args:
        document_path: Relative path for the document
        content: The text content to write
        overwrite: If True, overwrite existing files. Default is False.

    Returns:
        Dictionary containing write result and file metadata

    Example:
        result = write_customer_document(
            "reports/cust_123_monthly.txt",
            "Monthly report content...",
            overwrite=True
        )
    """
    full_path = Path(file_config.documents_dir) / document_path

    if full_path.exists() and not overwrite:
        return {"error": "File exists and overwrite=False", "path": str(full_path)}

    # Ensure parent directory exists
    full_path.parent.mkdir(parents=True, exist_ok=True)

    full_path.write_text(content)

    return {
        "status": "written",
        "path": str(full_path),
        "size_bytes": len(content.encode("utf-8")),
    }


@tool
def read_csv_file(
    filename: str,
    delimiter: str = ",",
    has_header: bool = True,
    max_rows: Optional[int] = None
) -> Dict[str, Any]:
    """
    Read a CSV file from the configured input directory.

    Parses CSV data and returns it as a list of records.
    This tool accesses the file system for read operations.

    Args:
        filename: Name of the CSV file in the input directory
        delimiter: Field delimiter character (default: comma)
        has_header: Whether the file has a header row (default: True)
        max_rows: Maximum number of rows to read (default: all)

    Returns:
        Dictionary containing parsed CSV data and metadata

    Example:
        data = read_csv_file("customer_export.csv", max_rows=1000)
    """
    full_path = Path(file_config.csv_input_dir) / filename

    if not full_path.exists():
        return {"error": "File not found", "path": str(full_path)}

    records = []
    with open(full_path, "r", newline="", encoding="utf-8") as f:
        if has_header:
            reader = csv.DictReader(f, delimiter=delimiter)
        else:
            reader = csv.reader(f, delimiter=delimiter)

        for i, row in enumerate(reader):
            if max_rows and i >= max_rows:
                break
            records.append(dict(row) if has_header else list(row))

    return {
        "path": str(full_path),
        "row_count": len(records),
        "records": records,
        "has_header": has_header,
    }


@tool
def list_documents(
    subdirectory: Optional[str] = None,
    pattern: str = "*"
) -> List[Dict[str, Any]]:
    """
    List documents in the documents directory.

    Returns a list of files matching the specified pattern.
    This is a read-only directory listing operation.

    Args:
        subdirectory: Optional subdirectory to search
        pattern: Glob pattern for filtering files (default: *)

    Returns:
        List of file metadata dictionaries

    Example:
        files = list_documents("contracts", pattern="*.pdf")
    """
    base_path = Path(file_config.documents_dir)
    if subdirectory:
        base_path = base_path / subdirectory

    if not base_path.exists():
        return []

    files = []
    for file_path in base_path.glob(pattern):
        if file_path.is_file():
            stat = file_path.stat()
            files.append({
                "name": file_path.name,
                "path": str(file_path.relative_to(file_config.documents_dir)),
                "size_bytes": stat.st_size,
                "modified_at": stat.st_mtime,
            })

    return files


@tool
def append_to_log(
    log_name: str,
    message: str,
    level: str = "INFO"
) -> Dict[str, Any]:
    """
    Append a message to a log file.

    Writes log entries to files in the documents directory.
    This tool performs append file operations.

    Args:
        log_name: Name of the log file (without path)
        message: The log message to append
        level: Log level (INFO, WARNING, ERROR)

    Returns:
        Dictionary with write status
    """
    import datetime

    log_path = Path(file_config.documents_dir) / "logs" / f"{log_name}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.utcnow().isoformat()
    log_entry = f"[{timestamp}] [{level}] {message}\n"

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(log_entry)

    return {"status": "logged", "path": str(log_path), "level": level}
