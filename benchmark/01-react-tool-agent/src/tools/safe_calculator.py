"""Safe calculator with proper authorization gate.

This demonstrates a TRUE NEGATIVE - a tool that SHOULD NOT be flagged
because it has a proper authorization decorator.
"""

from functools import wraps
from typing import Callable


class PermissionError(Exception):
    """Raised when permission is denied."""
    pass


def require_permission(permission: str) -> Callable:
    """Decorator that requires a specific permission to execute.

    This is a policy gate that WyScan should recognize.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check permission (simplified - in production would check user context)
            if not _check_permission(permission):
                raise PermissionError(f"Permission '{permission}' required")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def _check_permission(permission: str) -> bool:
    """Check if current context has the required permission."""
    # Simplified check - in production this would verify against auth system
    import os
    allowed = os.getenv("ALLOWED_PERMISSIONS", "").split(",")
    return permission in allowed


@require_permission("calculator:execute")
def safe_calculate(expression: str) -> str:
    """Safely evaluate a mathematical expression.

    This function uses eval() but is protected by @require_permission.
    WyScan should recognize this as a gated operation.

    Args:
        expression: Mathematical expression to evaluate

    Returns:
        String representation of the result
    """
    # This eval is protected by the @require_permission decorator
    # WyScan should detect the gate and not flag this as CRITICAL
    result = eval(expression)
    return str(result)


SAFE_CALCULATOR_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "safe_calculate",
            "description": "Safely evaluate a mathematical expression (requires permission)",
            "parameters": {
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "description": "Expression to evaluate"},
                },
                "required": ["expression"],
            },
        },
    },
]
