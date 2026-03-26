"""Document rewriter tool with self-poisoning vulnerability."""

import os
from pathlib import Path
from langchain_core.tools import tool


DOCUMENTS_DIR = Path(os.getenv("DOCUMENTS_DIR", "./documents"))


@tool
def read_document(doc_id: str) -> str:
    """Read a document from the RAG store.

    Args:
        doc_id: Document identifier (filename without extension)

    Returns:
        Document content
    """
    doc_path = DOCUMENTS_DIR / f"{doc_id}.txt"
    # AFB04 INFO: Read access to document store
    content = doc_path.read_text()
    return content


@tool
def execute_transform(transform_code: str, doc_content: str) -> str:
    """Execute a transformation on document content.

    VULNERABILITY: Executes arbitrary code via exec().

    Args:
        transform_code: Python code to transform the content
        doc_content: Document content to transform

    Returns:
        Transformed content
    """
    local_vars = {"content": doc_content, "result": ""}
    # AFB04 CRITICAL: exec() on LLM-generated code
    exec(transform_code, {"__builtins__": __builtins__}, local_vars)
    return local_vars.get("result", doc_content)


@tool
def rewrite_document(doc_id: str, new_content: str) -> str:
    """Rewrite a document in the RAG store.

    VULNERABILITY: Agent can modify its own knowledge base.
    Self-poisoning attack: malicious content persists and
    influences future queries.

    Args:
        doc_id: Document identifier
        new_content: New content to write

    Returns:
        Confirmation message
    """
    doc_path = DOCUMENTS_DIR / f"{doc_id}.txt"
    # AFB04 WARNING: Self-poisoning - agent modifies its knowledge base
    doc_path.write_text(new_content)
    return f"Document {doc_id} updated successfully"


@tool
def add_document(doc_id: str, content: str) -> str:
    """Add a new document to the RAG store.

    Args:
        doc_id: New document identifier
        content: Document content

    Returns:
        Confirmation message
    """
    new_doc_path = DOCUMENTS_DIR / f"{doc_id}.txt"
    # AFB04 WARNING: Agent can expand knowledge base
    new_doc_path.write_text(content)
    return f"Document {doc_id} added to store"
