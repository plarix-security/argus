"""
Authorization utilities for the Customer Operations Platform.

This module provides authentication and authorization checks used
throughout the platform to enforce access control policies.
"""

from functools import wraps
from typing import Callable, List, Optional, Any
from dataclasses import dataclass

from config import ROLE_PERMISSIONS, UserRole


class AuthorizationError(Exception):
    """Raised when a user lacks permission for an operation."""
    pass


class AuthenticationError(Exception):
    """Raised when user authentication fails."""
    pass


@dataclass
class User:
    """Represents an authenticated user."""

    user_id: str
    email: str
    role: str
    tenant_id: str

    def has_permission(self, permission: str) -> bool:
        """Check if user has the specified permission."""
        allowed = ROLE_PERMISSIONS.get(self.role, [])
        return permission in allowed


# Thread-local storage for current user context
_current_user: Optional[User] = None


def set_current_user(user: User) -> None:
    """Set the current user context for the request."""
    global _current_user
    _current_user = user


def get_current_user() -> Optional[User]:
    """Get the current authenticated user."""
    return _current_user


def check_permission(user: User, required_permission: str) -> bool:
    """
    Check if a user has the required permission.

    Args:
        user: The user to check permissions for
        required_permission: The permission string to check

    Returns:
        True if user has permission, False otherwise
    """
    if user is None:
        return False
    return user.has_permission(required_permission)


def require_permission(permission: str) -> Callable:
    """
    Decorator that enforces permission checks on functions.

    This decorator ensures the current user has the required permission
    before allowing the function to execute. If the check fails, it raises
    an AuthorizationError.

    Args:
        permission: The required permission string

    Returns:
        Decorated function that enforces the permission

    Raises:
        AuthorizationError: If user lacks the required permission
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            user = get_current_user()
            if user is None:
                raise AuthorizationError(
                    f"Authentication required for {func.__name__}"
                )
            if not check_permission(user, permission):
                raise AuthorizationError(
                    f"Permission '{permission}' required for {func.__name__}. "
                    f"User role '{user.role}' does not have this permission."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_admin(func: Callable) -> Callable:
    """
    Decorator that restricts a function to admin users only.

    Args:
        func: The function to protect

    Returns:
        Decorated function that only allows admin access

    Raises:
        AuthorizationError: If user is not an admin
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        user = get_current_user()
        if user is None:
            raise AuthorizationError(f"Authentication required for {func.__name__}")
        if user.role != UserRole.ADMIN:
            raise AuthorizationError(
                f"Admin access required for {func.__name__}. "
                f"Current role: {user.role}"
            )
        return func(*args, **kwargs)
    return wrapper


def validate_tenant_access(user: User, resource_tenant_id: str) -> bool:
    """
    Validate that a user can access resources from a specific tenant.

    Args:
        user: The user requesting access
        resource_tenant_id: The tenant ID of the resource

    Returns:
        True if access is allowed, False otherwise
    """
    if user is None:
        return False
    # Admins can access all tenants
    if user.role == UserRole.ADMIN:
        return True
    # Other users can only access their own tenant
    return user.tenant_id == resource_tenant_id
