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
]


def load_scopes_from_env() -> list[str]:
    """Load authorized scopes from environment variable"""
    env_scopes = os.environ.get("AUTHORIZED_SCOPES", "")
    if env_scopes:
        return [s.strip() for s in env_scopes.split(",") if s.strip()]
    return AUTHORIZED_SCOPES


def validate_scope(target: str) -> bool:
    """
    Validate if target is within authorized scope.
    
    Returns True if target is authorized, False otherwise.
    """
    if not target:
        return False
    
    # Sanitize input
    target = target.strip().lower()
    
    # Remove protocol if present
    target = re.sub(r'^https?://', '', target)
    
    # Remove path if present
    target = target.split('/')[0]
    
    # Remove port if present
    target = target.split(':')[0]
    
    scopes = load_scopes_from_env()
    
    for scope in scopes:
        scope = scope.strip().lower()
        
        # Check exact match
        if target == scope:
            return True
        
        # Check domain suffix
        if target.endswith(f".{scope}") or scope.endswith(f".{target}"):
            return True
        
        # Check IP range (CIDR notation)
        if '/' in scope:
            # Simplified CIDR check - just check the base
            base_ip = scope.split('/')[0]
            if target.startswith(base_ip.split('.')[0]):
                return True
        
        # Check private IP ranges
        private_ranges = [
            '10.',
            '192.168.',
            '172.16.',
            '172.17.',
            '172.18.',
            '172.19.',
            '172.20.',
            '172.21.',
            '172.22.',
            '172.23.',
            '172.24.',
            '172.25.',
            '172.26.',
            '172.27.',
            '172.28.',
            '172.29.',
            '172.30.',
            '172.31.',
            '127.',
            'localhost',
        ]
        
        for private_range in private_ranges:
            if target.startswith(private_range):
                return True
    
    return False


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
        
        if not validate_scope(target):
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
        "google.com",  # Should fail
        "evil.com",    # Should fail
    ]
    
    print("Scope Validation Tests:")
    print("-" * 40)
    
    for target in test_targets:
        result = validate_scope(target)
        status = "✓ AUTHORIZED" if result else "✗ DENIED"
        print(f"{target:20s} -> {status}")
