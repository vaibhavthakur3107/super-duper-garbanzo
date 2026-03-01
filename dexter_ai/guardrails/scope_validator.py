"""
Scope Validation Guardrail
Validates that targets are within authorized scope
"""

import os
import re
from typing import Optional


# Default authorized scopes (can be overridden by environment)
AUTHORIZED_SCOPES = [
    "example.com",
    "test.local",
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "testphp.vulnweb.com",
    "vulnweb.com",
    "test.vulnweb.com",
]


def _is_open_scope_mode() -> bool:
    """Return True when SCOPE_MODE=open, allowing any target."""
    return os.environ.get("SCOPE_MODE", "").strip().lower() == "open"


# Private IP prefixes that are always considered in-scope
_PRIVATE_RANGES = (
    '10.',
    '192.168.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
    '127.',
    'localhost',
)


def load_scopes_from_env() -> list[str]:
    """Load authorized scopes from environment variable"""
    env_scopes = os.environ.get("AUTHORIZED_SCOPES", "")
    if env_scopes:
        return [s.strip() for s in env_scopes.split(",") if s.strip()]
    return AUTHORIZED_SCOPES


def _check_target_against_scopes(target: str, scopes: list[str]) -> bool:
    """Core check: return True if *target* matches any entry in *scopes*."""
    target = target.strip().lower()

    for scope in scopes:
        scope = scope.strip().lower()

        # Exact match
        if target == scope:
            return True

        # Domain suffix match (subdomain ↔ parent domain)
        if target.endswith(f".{scope}") or scope.endswith(f".{target}"):
            return True

        # CIDR notation — simplified prefix check
        if '/' in scope:
            base_ip = scope.split('/')[0]
            if target.startswith(base_ip.split('.')[0]):
                return True

        # Private IP ranges always allowed
        for private_range in _PRIVATE_RANGES:
            if target.startswith(private_range):
                return True

    return False


def validate_scope(target: str) -> bool:
    """
    Validate if target is within authorized scope.

    When SCOPE_MODE=open any non-empty target is accepted, giving the same
    open-scope behaviour as tools like hexstrike-ai.  Set
    SCOPE_MODE=open in your .env to enable this mode.

    Returns True if target is authorized, False otherwise.
    """
    if not target:
        return False

    # Open-scope mode — accept everything (operator takes responsibility)
    if _is_open_scope_mode():
        return True

    # Sanitize input
    target = target.strip().lower()

    # Remove protocol if present
    target = re.sub(r'^https?://', '', target)

    # Remove path if present
    target = target.split('/')[0]

    # Remove port if present
    target = target.split(':')[0]

    return _check_target_against_scopes(target, load_scopes_from_env())


def validate_scope_with_list(target: str, scopes: list[str]) -> bool:
    """Validate *target* against an explicit *scopes* list.

    Useful when scopes are supplied at runtime (e.g. from the Streamlit UI)
    rather than read from the environment.  SCOPE_MODE=open still takes
    precedence.
    """
    if not target:
        return False
    if _is_open_scope_mode():
        return True

    # Sanitize
    target = target.strip().lower()
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    target = target.split(':')[0]

    return _check_target_against_scopes(target, scopes)


def get_authorized_scopes() -> list[str]:
    """Get list of currently authorized scopes"""
    return load_scopes_from_env()


def add_scope(scope: str) -> bool:
    """Add a new scope to the authorized list (returns success)"""
    # This would need to persist to a file or database in production
    if validate_scope(scope):
        return True
    return False


class ScopeValidator:
    """Class-based scope validator with additional features"""

    def __init__(self, scopes: Optional[list[str]] = None):
        self.scopes = scopes or load_scopes_from_env()

    def validate(self, target: str) -> tuple[bool, Optional[str]]:
        """Validate target and return (is_valid, reason_if_invalid)"""
        if not target:
            return False, "Empty target"

        if _is_open_scope_mode():
            return True, None

        if not validate_scope_with_list(target, self.scopes):
            return False, f"Target '{target}' is not in authorized scope"

        return True, None

    def get_scopes(self) -> list[str]:
        return self.scopes


# Example usage and testing
if __name__ == "__main__":
    # Test cases
    test_targets = [
        "example.com",
        "test.local",
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "google.com",  # Allowed only in open-scope mode
        "evil.com",    # Allowed only in open-scope mode
    ]

    mode = "OPEN" if _is_open_scope_mode() else "RESTRICTED"
    print(f"Scope Validation Tests  [SCOPE_MODE={mode}]:")
    print("-" * 40)

    for target in test_targets:
        result = validate_scope(target)
        status = "✓ AUTHORIZED" if result else "✗ DENIED"
        print(f"{target:20s} -> {status}")

