"""
Audit logging tools for multi-framework orchestrator
Demonstrates filesystem write vulnerability
"""

from pathlib import Path
from datetime import datetime
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

model = ChatOpenAI(model="gpt-4")

AUDIT_LOG_DIR = Path("/var/log/orchestrator")


def ensure_log_dir():
    """Ensure the audit log directory exists."""
    AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)


def write_audit_log(event_type: str, details: dict) -> dict:
    """Write an audit log entry.

    Args:
        event_type: Type of event being logged
        details: Event details

    Returns:
        dict: Log entry confirmation
    """
    ensure_log_dir()
    timestamp = datetime.now().isoformat()
    log_file = AUDIT_LOG_DIR / f"audit_{timestamp[:10]}.log"
    entry = f"[{timestamp}] {event_type}: {details}\n"
    # WARNING: Audit log write (incomplete cross-framework trace)
    log_file.write_text(entry)
    return {"logged": True, "file": str(log_file)}


tools = [write_audit_log]
agent = create_react_agent(model, tools)
