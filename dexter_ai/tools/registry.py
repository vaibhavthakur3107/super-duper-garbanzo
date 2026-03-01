"""
Tool Registry and Integrations
Manages all available tools for the Dexter AI Pentest agents
"""

import asyncio
import json
import socket
import whois
from datetime import datetime
from typing import Any, Optional
import logging

from .agents import Tool, ToolResult

logger = logging.getLogger(__name__)


class NetworkScannerTool(Tool):
    """Scans target for open ports and services"""
    
    def __init__(self):
        super().__init__(
            name="recon_target",
            description="Perform network reconnaissance on target",
            category="reconnaissance"
        )
    
    def validate_input(self, **kwargs) -> tuple[bool, Optional[str]]:
        target = kwargs.get("target", "")
        if not target:
            return False, "Target is required"
        if not self._is_valid_target(target):
            return False, "Invalid target format"
        return True, None
    
    def _is_valid_target(self, target: str) -> bool:
        # Basic validation - allows domain names and IP addresses
        pattern = r'^(?:[\w-]+\.)+[\w-]+$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(target and len(target) < 255)
    
    async def execute(self, **kwargs) -> ToolResult:
        target = kwargs.get("target", "")
        
        try:
            # Simulate port scanning (in production, use actual scanning)
            ports = await self._scan_ports(target)
            services = await self._identify_services(target, ports)
            
            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "open_ports": ports,
                    "services": services,
                    "scan_time": datetime.now().isoformat()
                }
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
    
    async def _scan_ports(self, target: str) -> list[dict]:
        """Simulate port scanning - returns common ports"""
        # In production, implement actual scanning with nmap or similar
        common_ports = [
            {"port": 80, "status": "open", "service": "http"},
            {"port": 443, "status": "open", "service": "https"},
            {"port": 22, "status": "open", "service": "ssh"},
            {"port": 21, "status": "closed", "service": "ftp"},
            {"port": 3306, "status": "closed", "service": "mysql"},
        ]
        await asyncio.sleep(0.5)  # Simulate scan time
        return common_ports
    
    async def _identify_services(self, target: str, ports: list[dict]) -> list[dict]:
        """Identify services running on open ports"""
        services = []
        for p in ports:
            if p["status"] == "open":
                services.append({
                    "port": p["port"],
                    "service": p["service"],
                    "version": "unknown",
                    "banner": f"{p['service']} banner grab"
                })
        return services


class VulnerabilityScannerTool(Tool):
    """Scans for known vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            name="scan_vulnerabilities",
            description="Scan target for known vulnerabilities",
            category="vulnerability"
        )
    
    def validate_input(self, **kwargs) -> tuple[bool, Optional[str]]:
        target = kwargs.get("target", "")
        if not target:
            return False, "Target is required"
        return True, None
    
    async def execute(self, **kwargs) -> ToolResult:
        target = kwargs.get("target", "")
        
        try:
            # Simulate vulnerability scanning
            vulns = await self._scan_vulnerabilities(target)
            
            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "vulnerabilities": vulns,
                    "scan_time": datetime.now().isoformat()
                }
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
    
    async def _scan_vulnerabilities(self, target: str) -> list[dict]:
        """Simulate vulnerability scanning"""
        # In production, integrate with vulnerability scanners
        await asyncio.sleep(0.5)
        
        return [
            {
                "cve": "CVE-2024-0001",
                "severity": "medium",
                "description": "Outdated web server version detected",
                "recommendation": "Update to latest version"
            },
            {
                "cve": "CVE-2024-0002",
                "severity": "low",
                "description": "Default SSL/TLS configuration",
                "recommendation": "Enable strong cipher suites"
            }
        ]


class WhoisLookupTool(Tool):
    """Performs WHOIS lookup on domains"""
    
    def __init__(self):
        super().__init__(
            name="whois_lookup",
            description="Perform WHOIS lookup on domain",
            category="reconnaissance"
        )
    
    def validate_input(self, **kwargs) -> tuple[bool, Optional[str]]:
        target = kwargs.get("target", "")
        if not target:
            return False, "Target domain is required"
        return True, None
    
    async def execute(self, **kwargs) -> ToolResult:
        target = kwargs.get("target", "")
        
        try:
            # Simulate WHOIS lookup
            result = await self._whois_lookup(target)
            
            return ToolResult(
                success=True,
                data=result
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
    
    async def _whois_lookup(self, target: str) -> dict:
        """Simulate WHOIS lookup"""
        await asyncio.sleep(0.3)
        
        return {
            "domain": target,
            "registrar": "Example Registrar",
            "created_date": "2023-01-01",
            "expiry_date": "2025-01-01",
            "name_servers": ["ns1.example.com", "ns2.example.com"],
            "status": "active"
        }


class SSLAnalysisTool(Tool):
    """Analyzes SSL/TLS configuration"""
    
    def __init__(self):
        super().__init__(
            name="ssl_analysis",
            description="Analyze SSL/TLS configuration of target",
            category="security"
        )
    
    def validate_input(self, **kwargs) -> tuple[bool, Optional[str]]:
        target = kwargs.get("target", "")
        if not target:
            return False, "Target is required"
        return True, None
    
    async def execute(self, **kwargs) -> ToolResult:
        target = kwargs.get("target", "")
        
        try:
            result = await self._analyze_ssl(target)
            
            return ToolResult(
                success=True,
                data=result
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
    
    async def _analyze_ssl(self, target: str) -> dict:
        """Simulate SSL analysis"""
        await asyncio.sleep(0.4)
        
        return {
            "target": target,
            "ssl_version": "TLS 1.2",
            "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
            "certificate_valid": True,
            "certificate_expiry": "2025-12-31",
            "issues": [
                {
                    "severity": "low",
                    "message": "TLS 1.3 not enabled"
                }
            ]
        }


class AnalyzeEnvironmentTool(Tool):
    """Analyzes the current environment and available resources"""
    
    def __init__(self):
        super().__init__(
            name="analyze_environment",
            description="Analyze the current environment and context",
            category="analysis"
        )
    
    def validate_input(self, **kwargs) -> tuple[bool, Optional[str]]:
        return True, None
    
    async def execute(self, **kwargs) -> ToolResult:
        prompt = kwargs.get("prompt", "")
        
        return ToolResult(
            success=True,
            data={
                "analysis": "Environment analysis complete",
                "prompt": prompt[:100],
                "capabilities": [
                    "network_scanning",
                    "vulnerability_assessment",
                    "ssl_analysis",
                    "whois_lookup",
                    "exploit_validation"
                ]
            }
        )


class ListCapabilitiesTool(Tool):
    """Lists all available agent capabilities"""
    
    def __init__(self):
        super().__init__(
            name="list_capabilities",
            description="List all available agent capabilities",
            category="utility"
        )
    
    def validate_input(self, **kwargs) -> tuple[bool, Optional[str]]:
        return True, None
    
    async def execute(self, **kwargs) -> ToolResult:
        return ToolResult(
            success=True,
            data={
                "capabilities": [
                    {
                        "name": "recon_target",
                        "description": "Perform network reconnaissance",
                        "category": "reconnaissance"
                    },
                    {
                        "name": "scan_vulnerabilities",
                        "description": "Scan for known vulnerabilities",
                        "category": "vulnerability"
                    },
                    {
                        "name": "ssl_analysis",
                        "description": "Analyze SSL/TLS configuration",
                        "category": "security"
                    },
                    {
                        "name": "whois_lookup",
                        "description": "Perform WHOIS lookup",
                        "category": "reconnaissance"
                    },
                    {
                        "name": "validate_exploits",
                        "description": "Validate potential exploits",
                        "category": "exploitation"
                    },
                    {
                        "name": "generate_report",
                        "description": "Generate assessment report",
                        "category": "reporting"
                    }
                ]
            }
        )


class ToolRegistry:
    """Registry for all available tools"""
    
    def __init__(self):
        self.tools: dict[str, Tool] = {}
        self._register_default_tools()
    
    def _register_default_tools(self):
        tools = [
            NetworkScannerTool(),
            VulnerabilityScannerTool(),
            WhoisLookupTool(),
            SSLAnalysisTool(),
            AnalyzeEnvironmentTool(),
            ListCapabilitiesTool(),
        ]
        
        for tool in tools:
            self.register(tool)
    
    def register(self, tool: Tool):
        self.tools[tool.name] = tool
        logger.info(f"Registered tool: {tool.name}")
    
    def get(self, name: str) -> Optional[Tool]:
        return self.tools.get(name)
    
    def list_tools(self) -> list[dict]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category
            }
            for t in self.tools.values()
        ]
    
    def get_by_category(self, category: str) -> list[Tool]:
        return [t for t in self.tools.values() if t.category == category]
