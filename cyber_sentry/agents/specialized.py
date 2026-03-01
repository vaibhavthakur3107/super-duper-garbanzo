"""
Specialized Red Team Agents
Each agent has a specific role in the cyber security assessment workflow
"""

import asyncio
import re
from dataclasses import dataclass
from typing import Optional

from . import Agent, AgentConfig, AgentState, Thought, Tool, ToolResult, Guardrail
from ..tools.registry import ToolRegistry
from ..guardrails.security import SecurityGuardrails


@dataclass
class ReconnaissanceAgent(Agent):
    """Agent responsible for information gathering and reconnaissance"""
    
    async def _reason(self, prompt: str) -> str:
        # Extract potential targets from prompt
        targets = re.findall(r'(?:https?://)?(?:[\w-]+\.)+[\w-]+', prompt)
        target = targets[0] if targets else "unknown"
        self.context["target"] = target
        
        reasoning = f"""
Target identified: {target}
Strategy: Conduct passive reconnaissance first, then active scanning
Priority: Gather open-source intelligence, identify attack surface
"""
        return reasoning.strip()
    
    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        target = self.context.get("target", "")
        
        if not target:
            return "analyze_environment", {"prompt": prompt}
        
        if "http" in target.lower() or "." in target:
            return "recon_target", {"target": target}
        
        return "list_capabilities", {}
    
    async def _act(self, action: str, params: dict) -> str:
        result = await super()._act(action, params)
        
        # Update context with findings
        if action == "recon_target":
            self.context["recon_done"] = True
            self.context["findings"] = {
                "ports_found": [],
                "services_found": [],
                "vulnerabilities": []
            }
        
        return result


@dataclass
class VulnerabilityAgent(Agent):
    """Agent responsible for vulnerability analysis and assessment"""
    
    async def _reason(self, prompt: str) -> str:
        reasoning = """
Strategy: Analyze discovered services for known vulnerabilities
Focus: CVEs, misconfigurations, default credentials, outdated software
Priority: High-severity findings first
"""
        return reasoning.strip()
    
    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        target = self.context.get("target", "")
        
        if target:
            return "scan_vulnerabilities", {"target": target}
        
        return "request_target", {"message": "Need target for vulnerability scanning"}
    
    async def _act(self, action: str, params: dict) -> str:
        result = await super()._act(action, params)
        
        if action == "scan_vulnerabilities":
            self.context["vuln_scan_done"] = True
        
        return result


@dataclass
class ExploitationAgent(Agent):
    """Agent responsible for exploit validation and testing"""
    
    async def _reason(self, prompt: str) -> str:
        reasoning = """
Strategy: Validate potential exploits in a controlled manner
Focus: Proof-of-concept development, safe exploitation techniques
Constraints: Must stay within scope and legal boundaries
"""
        return reasoning.strip()
    
    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        target = self.context.get("target", "")
        vuln_scan_done = self.context.get("vuln_scan_done", False)
        
        if target and vuln_scan_done:
            return "validate_exploits", {"target": target}
        
        return "wait_for_vuln_scan", {}
    
    async def _act(self, action: str, params: dict) -> str:
        result = await super()._act(action, params)
        
        if action == "validate_exploits":
            self.context["exploit_validation_done"] = True
        
        return result


@dataclass
class ReportingAgent(Agent):
    """Agent responsible for generating assessment reports"""
    
    async def _reason(self, prompt: str) -> str:
        reasoning = """
Strategy: Compile comprehensive assessment report
Focus: Findings, risk ratings, remediation recommendations
Format: Executive summary + technical details
"""
        return reasoning.strip()
    
    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        target = self.context.get("target", "")
        
        if target:
            return "generate_report", {"target": target}
        
        return "generate_empty_report", {}
    
    async def _act(self, action: str, params: dict) -> str:
        result = await super()._act(action, params)
        
        if action == "generate_report":
            report_data = {
                "target": params.get("target"),
                "findings": self.context.get("findings", []),
                "vulnerabilities": self.context.get("vulnerabilities", []),
                "risk_level": "Medium"
            }
            self.context["report"] = report_data
            return f"Report generated for {params.get('target')}"
        
        return result


class AgentFactory:
    """Factory for creating specialized agents"""
    
    def __init__(self, tool_registry: ToolRegistry, guardrails: list[Guardrail]):
        self.tool_registry = tool_registry
        self.guardrails = guardrails
    
    def create_reconnaissance_agent(self) -> ReconnaissanceAgent:
        config = AgentConfig(
            name="Reconnaissance Agent",
            description="Gathers intelligence about target systems",
            system_prompt="You are an expert at OSINT and network reconnaissance.",
            max_iterations=5,
            tools=["recon_target", "analyze_environment", "list_capabilities"]
        )
        return ReconnaissanceAgent(config, self.tool_registry.tools, self.guardrails)
    
    def create_vulnerability_agent(self) -> VulnerabilityAgent:
        config = AgentConfig(
            name="Vulnerability Agent",
            description="Analyzes systems for security vulnerabilities",
            system_prompt="You are an expert at vulnerability assessment and CVE analysis.",
            max_iterations=5,
            tools=["scan_vulnerabilities", "check_cves"]
        )
        return VulnerabilityAgent(config, self.tool_registry.tools, self.guardrails)
    
    def create_exploitation_agent(self) -> ExploitationAgent:
        config = AgentConfig(
            name="Exploitation Agent",
            description="Validates and tests potential exploits safely",
            system_prompt="You are an expert at safe exploit validation and red team operations.",
            max_iterations=3,
            tools=["validate_exploits", "test_payload"]
        )
        return ExploitationAgent(config, self.tool_registry.tools, self.guardrails)
    
    def create_reporting_agent(self) -> ReportingAgent:
        config = AgentConfig(
            name="Reporting Agent",
            description="Generates comprehensive security assessment reports",
            system_prompt="You are an expert at technical writing and security reporting.",
            max_iterations=2,
            tools=["generate_report", "export_report"]
        )
        return ReportingAgent(config, self.tool_registry.tools, self.guardrails)
    
    def create_all_agents(self) -> list[Agent]:
        return [
            self.create_reconnaissance_agent(),
            self.create_vulnerability_agent(),
            self.create_exploitation_agent(),
            self.create_reporting_agent()
        ]
