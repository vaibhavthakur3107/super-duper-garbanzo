"""
Security Guardrails
Implements safety checks and ethical boundaries for agent operations
"""

import asyncio
import re
from typing import Any, Optional

from ..agents import Guardrail, ToolResult


class ScopeValidationGuardrail(Guardrail):
    """Validates that target is within allowed scope"""
    
    def __init__(self, allowed_domains: list[str] = None):
        super().__init__(
            name="scope_validation",
            description="Validates target is within allowed scope"
        )
        self.allowed_domains = allowed_domains or [
            "example.com",
            "test.local",
            "127.0.0.1",
            "localhost"
        ]
    
    async def check(self, action: str, params: dict, context: dict) -> tuple[bool, Optional[str]]:
        target = params.get("target", "")
        
        if not target:
            return True, None
        
        # Check if target is in allowed domains or is a private IP
        if self._is_allowed(target):
            return True, None
        
        return False, f"Target '{target}' is not in allowed scope"
    
    def _is_allowed(self, target: str) -> bool:
        # Check against allowed domains
        for domain in self.allowed_domains:
            if target.endswith(domain) or target == domain:
                return True
        
        # Check for private IP ranges
        if target.startswith(("10.", "192.168.", "172.16.", "127.")):
            return True
        
        # Allow localhost
        if target in ("localhost", "0.0.0.0"):
            return True
        
        return False


class DangerousActionGuardrail(Guardrail):
    """Blocks potentially dangerous or harmful actions"""
    
    DANGEROUS_ACTIONS = [
        "execute_arbitrary_code",
        "delete_data",
        "modify_data",
        "install_malware",
        "denial_of_service",
        "exploit_remote",
        "privilege_escalation"
    ]
    
    def __init__(self):
        super().__init__(
            name="dangerous_action",
            description="Blocks dangerous or harmful actions"
        )
    
    async def check(self, action: str, params: dict, context: dict) -> tuple[bool, Optional[str]]:
        # Check for dangerous actions
        for dangerous in self.DANGEROUS_ACTIONS:
            if dangerous in action.lower():
                return False, f"Action '{action}' is not allowed"
        
        # Check for destructive parameters
        if params.get("destructive") or params.get("force"):
            return False, "Destructive operations are not allowed"
        
        return True, None


class RateLimitGuardrail(Guardrail):
    """Enforces rate limiting to prevent abuse"""
    
    def __init__(self, max_requests_per_minute: int = 60):
        super().__init__(
            name="rate_limit",
            description="Enforces rate limiting"
        )
        self.max_requests = max_requests_per_minute
        self.request_counts: dict[str, list[float]] = {}
    
    async def check(self, action: str, params: dict, context: dict) -> tuple[bool, Optional[str]]:
        agent = context.get("agent", "unknown")
        current_time = asyncio.get_event_loop().time()
        
        if agent not in self.request_counts:
            self.request_counts[agent] = []
        
        # Clean old requests (older than 1 minute)
        self.request_counts[agent] = [
            t for t in self.request_counts[agent]
            if current_time - t < 60
        ]
        
        # Check rate limit
        if len(self.request_counts[agent]) >= self.max_requests:
            return False, f"Rate limit exceeded for {agent}"
        
        # Record this request
        self.request_counts[agent].append(current_time)
        
        return True, None


class InputValidationGuardrail(Guardrail):
    """Validates and sanitizes inputs"""
    
    def __init__(self):
        super().__init__(
            name="input_validation",
            description="Validates and sanitizes inputs"
        )
        # Block common injection patterns
        self.blocked_patterns = [
            r"[\;\|\`\$\(\)]",  # Shell metacharacters
            r"<script",  # XSS attempts
            r"javascript:",  # XSS attempts
            r"on\w+\s*=",  # Event handlers
            r"union\s+select",  # SQL injection
            r"\.\./",  # Path traversal
        ]
    
    async def check(self, action: str, params: dict, context: dict) -> tuple[bool, Optional[str]]:
        # Check all string parameters
        for key, value in params.items():
            if isinstance(value, str):
                for pattern in self.blocked_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        return False, f"Invalid input detected in {key}"
        
        return True, None


class LegalComplianceGuardrail(Guardrail):
    """Ensures operations comply with legal requirements"""
    
    def __init__(self):
        super().__init__(
            name="legal_compliance",
            description="Ensures legal compliance"
        )
    
    async def check(self, action: str, params: dict, context: dict) -> tuple[bool, Optional[str]]:
        target = params.get("target", "")
        
        # Block scanning of government or critical infrastructure
        blocked_prefixes = [
            ".gov",
            ".mil",
            "gov.",
            "whitehouse.gov",
            "cia.gov",
            "fbi.gov"
        ]
        
        for prefix in blocked_prefixes:
            if prefix in target.lower():
                return False, "Scanning government sites is not allowed"
        
        return True, None


class OutputFilteringGuardrail(Guardrail):
    """Filters sensitive information from outputs"""
    
    def __init__(self):
        super().__init__(
            name="output_filtering",
            description="Filters sensitive information from outputs"
        )
        self.sensitive_patterns = [
            (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]'),  # SSN
            (r'\b\d{16}\b', '[CREDIT_CARD]'),  # Credit card
            (r'password\s*[=:]\s*\S+', 'password=[REDACTED]'),
            (r'api[_-]?key\s*[=:]\s*\S+', 'api_key=[REDACTED]'),
            (r'secret\s*[=:]\s*\S+', 'secret=[REDACTED]'),
        ]
    
    async def check(self, action: str, params: dict, context: dict) -> tuple[bool, Optional[str]]:
        return True, None  # This is for output filtering, not input blocking
    
    def filter_output(self, output: str) -> str:
        """Filter sensitive data from output"""
        for pattern, replacement in self.sensitive_patterns:
            output = re.sub(pattern, replacement, output, flags=re.IGNORECASE)
        return output


class AuditLoggingGuardrail(Guardrail):
    """Logs all operations for audit purposes"""
    
    def __init__(self):
        super().__init__(
            name="audit_logging",
            description="Logs all operations for audit"
        )
        self.audit_log: list[dict] = []
    
    async def check(self, action: str, params: dict, context: dict) -> tuple[bool, Optional[str]]:
        # Log the action
        self.audit_log.append({
            "timestamp": asyncio.get_event_loop().time(),
            "agent": context.get("agent"),
            "action": action,
            "params": params,
            "target": params.get("target", "")
        })
        
        return True, None
    
    def get_audit_log(self) -> list[dict]:
        return self.audit_log


class SecurityGuardrails:
    """Collection of all security guardrails"""
    
    def __init__(self, allowed_domains: list[str] = None):
        self.guardrails: list[Guardrail] = [
            ScopeValidationGuardrail(allowed_domains),
            DangerousActionGuardrail(),
            RateLimitGuardrail(),
            InputValidationGuardrail(),
            LegalComplianceGuardrail(),
            OutputFilteringGuardrail(),
            AuditLoggingGuardrail()
        ]
    
    def add_guardrail(self, guardrail: Guardrail):
        self.guardrails.append(guardrail)
    
    def get_guardrail(self, name: str) -> Optional[Guardrail]:
        for g in self.guardrails:
            if g.name == name:
                return g
        return None
    
    def list_guardrails(self) -> list[dict]:
        return [
            {
                "name": g.name,
                "description": g.description
            }
            for g in self.guardrails
        ]
