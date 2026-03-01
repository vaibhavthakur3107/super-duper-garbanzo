"""
Autonomous Pentesting Engine & Team of Specialists
AI-powered autonomous agent that determines and executes penetration testing steps.
Delegation system with specialized AI agents for research, development, and infrastructure.
Inspired by pentagi's autonomous execution and specialist delegation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Specialist dataclass & team
# ---------------------------------------------------------------------------

@dataclass
class Specialist:
    """Represents a specialist agent in the pentesting team."""

    name: str
    role: str
    description: str
    capabilities: list[str] = field(default_factory=list)
    status: str = "idle"


# Pre-defined specialist definitions
_SPECIALIST_DEFS = [
    Specialist(
        name="ReconSpecialist",
        role="reconnaissance",
        description="Performs host discovery, port scanning, DNS enumeration, and OSINT gathering.",
        capabilities=["reconnaissance", "osint", "enumeration"],
    ),
    Specialist(
        name="WebSpecialist",
        role="web",
        description="Tests web applications for OWASP Top 10 vulnerabilities, API security, and logic flaws.",
        capabilities=["vulnerability", "web", "api_security"],
    ),
    Specialist(
        name="NetworkSpecialist",
        role="network",
        description="Analyzes network infrastructure, protocols, services, and configurations.",
        capabilities=["reconnaissance", "enumeration", "infrastructure"],
    ),
    Specialist(
        name="ExploitSpecialist",
        role="exploit",
        description="Develops and validates exploits, performs post-exploitation, and tests payloads.",
        capabilities=["exploitation", "authentication", "binary"],
    ),
    Specialist(
        name="ForensicsSpecialist",
        role="forensics",
        description="Conducts memory forensics, binary analysis, steganography, and artifact recovery.",
        capabilities=["forensics", "binary", "ctf"],
    ),
    Specialist(
        name="CloudSpecialist",
        role="cloud",
        description="Assesses cloud configurations, container security, and infrastructure-as-code.",
        capabilities=["cloud", "infrastructure"],
    ),
    Specialist(
        name="ReportSpecialist",
        role="reporting",
        description="Generates detailed vulnerability reports, risk assessments, and remediation plans.",
        capabilities=["reporting", "documentation"],
    ),
]

# Keyword-to-role mapping for task delegation
_ROLE_KEYWORDS = {
    "reconnaissance": [
        "scan", "discover", "enumerate", "dns", "subdomain", "recon",
        "whois", "nmap", "port", "host discovery",
    ],
    "web": [
        "web", "http", "xss", "sqli", "injection", "owasp", "api",
        "directory", "brute", "fuzz", "spider", "crawl", "waf",
    ],
    "network": [
        "network", "protocol", "smb", "snmp", "ftp", "ssh", "tcp",
        "udp", "firewall", "routing", "vlan",
    ],
    "exploit": [
        "exploit", "payload", "shell", "reverse", "metasploit", "rce",
        "privilege", "escalation", "post-exploit", "lateral",
    ],
    "forensics": [
        "forensic", "memory", "binary", "reverse engineer", "malware",
        "stego", "artifact", "disk", "ctf",
    ],
    "cloud": [
        "cloud", "aws", "azure", "gcp", "kubernetes", "docker",
        "container", "terraform", "iam", "s3",
    ],
    "reporting": [
        "report", "document", "summary", "executive", "remediation",
        "risk", "compliance",
    ],
}


class SpecialistTeam:
    """Manages a team of specialist agents and delegates tasks."""

    def __init__(self):
        self._specialists: dict[str, Specialist] = {}
        for spec in _SPECIALIST_DEFS:
            self._specialists[spec.role] = Specialist(
                name=spec.name,
                role=spec.role,
                description=spec.description,
                capabilities=list(spec.capabilities),
                status=spec.status,
            )

    def get_specialist(self, role: str) -> Optional[Specialist]:
        """Retrieve a specialist by role name."""
        return self._specialists.get(role)

    def list_specialists(self) -> list[Specialist]:
        """Return all specialists in the team."""
        return list(self._specialists.values())

    def delegate_task(self, task: str, context: Optional[dict] = None) -> dict:
        """Assign a task to the best-matched specialist based on keywords.

        Returns a dict with ``specialist``, ``task``, ``context``, and ``assigned_at``.
        """
        context = context or {}
        task_lower = task.lower()
        best_role: Optional[str] = None
        best_score = 0

        for role, keywords in _ROLE_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in task_lower)
            if score > best_score:
                best_score = score
                best_role = role

        # Default to reconnaissance if no keywords matched
        if best_role is None:
            best_role = "reconnaissance"

        specialist = self._specialists[best_role]
        specialist.status = "assigned"

        return {
            "specialist": specialist.name,
            "role": specialist.role,
            "task": task,
            "context": context,
            "assigned_at": datetime.now().isoformat(),
        }

    def get_team_status(self) -> dict:
        """Return a status summary for every specialist."""
        return {
            "team_size": len(self._specialists),
            "specialists": [
                {
                    "name": s.name,
                    "role": s.role,
                    "status": s.status,
                    "capabilities": s.capabilities,
                }
                for s in self._specialists.values()
            ],
        }


# ---------------------------------------------------------------------------
# Autonomous pentesting engine
# ---------------------------------------------------------------------------

# Ordered phase definitions
_PHASES = [
    {
        "name": "reconnaissance",
        "description": "Discover targets, open ports, running services, and technology stack.",
        "tools": ["nmap", "rustscan", "subfinder", "amass_enum", "whatweb"],
        "specialist": "reconnaissance",
    },
    {
        "name": "enumeration",
        "description": "Deep-dive into discovered services — extract versions, banners, directories.",
        "tools": ["gobuster", "feroxbuster", "ffuf", "enum4linux", "smbmap"],
        "specialist": "network",
    },
    {
        "name": "vulnerability_scan",
        "description": "Scan for known vulnerabilities and misconfigurations.",
        "tools": ["nuclei", "nikto", "wpscan", "testssl", "trivy_scan"],
        "specialist": "web",
    },
    {
        "name": "exploitation_validation",
        "description": "Validate exploitability of discovered vulnerabilities (non-destructive).",
        "tools": ["sqlmap", "dalfox", "commix", "searchsploit"],
        "specialist": "exploit",
    },
    {
        "name": "post_exploitation",
        "description": "Assess lateral movement, privilege escalation, and data exposure.",
        "tools": ["hydra", "hashcat", "bloodhound-python"],
        "specialist": "exploit",
    },
    {
        "name": "reporting",
        "description": "Compile findings into a detailed penetration test report.",
        "tools": [],
        "specialist": "reporting",
    },
]


class AutonomousEngine:
    """AI-powered autonomous penetration testing engine.

    Plans, executes, and adapts assessment phases based on progressive findings.
    """

    def __init__(self):
        self._team = SpecialistTeam()
        self._findings: list[dict] = []
        self._executed_phases: list[dict] = []

    def plan_assessment(self, target: str, task: str = "") -> list[dict]:
        """Create an ordered list of assessment phases for the target.

        Parameters
        ----------
        target : str
            Primary target (IP, domain, URL).
        task : str, optional
            High-level task description used to tailor the plan.

        Returns
        -------
        list[dict]
            Ordered list of phase dicts with ``name``, ``description``, ``tools``,
            ``specialist``, and ``target``.
        """
        plan = []
        task_lower = task.lower()

        for phase in _PHASES:
            # Always include recon and reporting; skip others only when task
            # is very narrow and clearly irrelevant
            include = True
            if task_lower:
                if phase["name"] == "post_exploitation" and "recon" in task_lower:
                    include = False
                elif phase["name"] == "exploitation_validation" and "recon" in task_lower:
                    include = False

            if include:
                plan.append({
                    **phase,
                    "target": target,
                    "status": "pending",
                })
        return plan

    def determine_next_step(self, current_state: dict, findings: list[dict]) -> dict:
        """Decide the next action based on current progress and findings.

        Parameters
        ----------
        current_state : dict
            Must include ``completed_phases`` (list of names) and ``target``.
        findings : list[dict]
            Accumulated findings so far.

        Returns
        -------
        dict
            Keys: ``action`` (phase name or "complete"), ``reason``, ``priority``,
            ``specialist``.
        """
        completed = set(current_state.get("completed_phases", []))
        target = current_state.get("target", "")

        # Walk through canonical phase order
        for phase in _PHASES:
            if phase["name"] in completed:
                continue

            # Adapt based on findings
            reason = f"Next phase in assessment pipeline for {target}."
            priority = "normal"

            if phase["name"] == "exploitation_validation" and not findings:
                reason = "No vulnerabilities found yet — skipping exploitation validation."
                continue

            if phase["name"] == "post_exploitation":
                has_confirmed = any(
                    f.get("category") in ("vulnerability", "exploit") for f in findings
                )
                if not has_confirmed:
                    reason = "No confirmed vulnerabilities — skipping post-exploitation."
                    continue
                priority = "high"
                reason = "Confirmed vulnerabilities found — validating post-exploitation paths."

            return {
                "action": phase["name"],
                "reason": reason,
                "priority": priority,
                "specialist": phase["specialist"],
            }

        return {
            "action": "complete",
            "reason": "All applicable phases have been executed.",
            "priority": "normal",
            "specialist": "reporting",
        }

    def execute_phase(self, phase: dict, target: str) -> dict:
        """Simulate executing an assessment phase.

        In a live environment this would invoke real tools; here it records
        the phase execution with metadata.

        Returns
        -------
        dict
            Phase result with ``phase``, ``target``, ``status``, ``started_at``,
            ``completed_at``, ``tools_used``, ``findings``, and ``specialist``.
        """
        started_at = datetime.now().isoformat()
        phase_name = phase.get("name", phase.get("action", "unknown"))
        specialist_role = phase.get("specialist", "reconnaissance")
        delegation = self._team.delegate_task(
            f"Execute {phase_name} against {target}",
            context={"phase": phase_name, "target": target},
        )

        # Record result (simulation — real execution would call tool wrappers)
        result = {
            "phase": phase_name,
            "target": target,
            "status": "completed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            "tools_used": phase.get("tools", []),
            "findings": [],
            "specialist": delegation["specialist"],
        }

        # Mark specialist back to idle
        spec = self._team.get_specialist(specialist_role)
        if spec:
            spec.status = "idle"

        self._executed_phases.append(result)
        return result

    def _calculate_risk(self, findings: list[dict]) -> float:
        """Calculate a simple risk score (0-10) from accumulated findings."""
        if not findings:
            return 0.0
        weights = {"critical": 10.0, "high": 8.0, "medium": 5.0, "low": 2.0}
        total = 0.0
        for f in findings:
            cat = f.get("category", "").lower()
            if "critical" in cat or "rce" in f.get("content", "").lower():
                total += weights["critical"]
            elif "high" in cat or "exploit" in cat:
                total += weights["high"]
            elif "vulnerability" in cat:
                total += weights["medium"]
            else:
                total += weights["low"]
        score = min(10.0, total / max(len(findings), 1) + min(len(findings) * 0.5, 4.0))
        return round(score, 1)

    def run_autonomous(
        self,
        target: str,
        task: str = "",
        max_phases: int = 10,
    ) -> dict:
        """Execute a full autonomous penetration test.

        Parameters
        ----------
        target : str
            Primary target.
        task : str, optional
            High-level goal.
        max_phases : int
            Safety limit on the number of phases to execute.

        Returns
        -------
        dict
            Summary with ``target``, ``task``, ``phases_executed``, ``findings``,
            ``risk_score``, ``team_status``, ``started_at``, and ``completed_at``.
        """
        started_at = datetime.now().isoformat()
        plan = self.plan_assessment(target, task)
        self._findings = []
        self._executed_phases = []

        current_state = {"completed_phases": [], "target": target}

        for _ in range(max_phases):
            step = self.determine_next_step(current_state, self._findings)
            if step["action"] == "complete":
                break

            # Find the matching phase from the plan
            phase = next(
                (p for p in plan if p["name"] == step["action"]),
                {"name": step["action"], "tools": [], "specialist": step["specialist"]},
            )
            result = self.execute_phase(phase, target)
            current_state["completed_phases"].append(step["action"])

            # Accumulate findings
            self._findings.extend(result.get("findings", []))

        return {
            "target": target,
            "task": task or "Comprehensive penetration test",
            "phases_executed": [p["phase"] for p in self._executed_phases],
            "phase_results": self._executed_phases,
            "findings": self._findings,
            "risk_score": self._calculate_risk(self._findings),
            "team_status": self._team.get_team_status(),
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
        }


# Module-level singleton instances
specialist_team = SpecialistTeam()
autonomous_engine = AutonomousEngine()
