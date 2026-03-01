"""
CVE Intelligence Manager
Vulnerability intelligence with CVE monitoring, severity tracking,
and exploit analysis. Inspired by hexstrike-ai and pentagi.
"""

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class Severity(enum.Enum):
    """CVE severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CVEEntry:
    """A single CVE record."""

    cve_id: str
    severity: Severity
    description: str
    affected_products: list[str] = field(default_factory=list)
    cvss_score: float = 0.0
    published_date: str = ""
    references: list[str] = field(default_factory=list)
    exploits_available: bool = False


# ── Built-in CVE database for common services ───────────────────────────────

_BUILTIN_CVES: list[CVEEntry] = [
    CVEEntry(
        cve_id="CVE-2021-44228",
        severity=Severity.CRITICAL,
        description="Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints (Log4Shell).",
        affected_products=["apache:log4j"],
        cvss_score=10.0,
        published_date="2021-12-10",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        exploits_available=True,
    ),
    CVEEntry(
        cve_id="CVE-2021-41773",
        severity=Severity.CRITICAL,
        description="Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49.",
        affected_products=["apache:http_server:2.4.49"],
        cvss_score=9.8,
        published_date="2021-10-05",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        exploits_available=True,
    ),
    CVEEntry(
        cve_id="CVE-2023-44487",
        severity=Severity.HIGH,
        description="HTTP/2 Rapid Reset attack allows denial of service (affects nginx, Apache, and other HTTP/2 servers).",
        affected_products=["nginx", "apache:http_server"],
        cvss_score=7.5,
        published_date="2023-10-10",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
        exploits_available=True,
    ),
    CVEEntry(
        cve_id="CVE-2023-38408",
        severity=Severity.CRITICAL,
        description="OpenSSH before 9.3p2 allows remote code execution via a crafted PKCS#11 provider.",
        affected_products=["openssh:openssh"],
        cvss_score=9.8,
        published_date="2023-07-20",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
        exploits_available=False,
    ),
    CVEEntry(
        cve_id="CVE-2022-0778",
        severity=Severity.HIGH,
        description="Infinite loop in BN_mod_sqrt() reachable when parsing certificates (OpenSSL).",
        affected_products=["openssl:openssl"],
        cvss_score=7.5,
        published_date="2022-03-15",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-0778"],
        exploits_available=True,
    ),
    CVEEntry(
        cve_id="CVE-2023-22515",
        severity=Severity.CRITICAL,
        description="Broken access control in Atlassian Confluence Data Center and Server allows an attacker to create unauthorized admin accounts.",
        affected_products=["atlassian:confluence"],
        cvss_score=10.0,
        published_date="2023-10-04",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"],
        exploits_available=True,
    ),
    CVEEntry(
        cve_id="CVE-2021-26855",
        severity=Severity.CRITICAL,
        description="Microsoft Exchange Server SSRF vulnerability (ProxyLogon).",
        affected_products=["microsoft:exchange_server"],
        cvss_score=9.8,
        published_date="2021-03-02",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
        exploits_available=True,
    ),
    CVEEntry(
        cve_id="CVE-2023-36884",
        severity=Severity.HIGH,
        description="Microsoft Office and Windows HTML remote code execution vulnerability.",
        affected_products=["microsoft:office", "microsoft:windows"],
        cvss_score=8.3,
        published_date="2023-07-11",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-36884"],
        exploits_available=True,
    ),
    CVEEntry(
        cve_id="CVE-2023-3817",
        severity=Severity.MEDIUM,
        description="Excessive time spent checking DH q parameter value in OpenSSL.",
        affected_products=["openssl:openssl"],
        cvss_score=5.3,
        published_date="2023-07-31",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-3817"],
        exploits_available=False,
    ),
    CVEEntry(
        cve_id="CVE-2022-27228",
        severity=Severity.CRITICAL,
        description="MySQL Server optimizer vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server.",
        affected_products=["oracle:mysql"],
        cvss_score=9.8,
        published_date="2022-04-19",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-27228"],
        exploits_available=False,
    ),
]


class CVEIntelligence:
    """
    Local CVE intelligence database for correlation with scan results.

    Pre-loaded with commonly referenced CVEs.  Additional entries can be
    added via :meth:`add_cve`.
    """

    def __init__(self, preload: bool = True):
        self._db: dict[str, CVEEntry] = {}
        if preload:
            for entry in _BUILTIN_CVES:
                self._db[entry.cve_id] = entry

    # ── Public API ───────────────────────────────────────────────────────────

    def add_cve(self, entry: CVEEntry) -> None:
        """Add or update a CVE entry in the local database."""
        self._db[entry.cve_id] = entry

    def lookup_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Return a single CVE by its ID, or ``None``."""
        return self._db.get(cve_id.upper())

    def search_cve(self, query: str) -> list[CVEEntry]:
        """
        Search local database by keyword.

        Matches against CVE ID, description, and affected products.
        """
        query_lower = query.lower()
        results: list[CVEEntry] = []
        for entry in self._db.values():
            if query_lower in entry.cve_id.lower():
                results.append(entry)
                continue
            if query_lower in entry.description.lower():
                results.append(entry)
                continue
            if any(query_lower in p.lower() for p in entry.affected_products):
                results.append(entry)
        return results

    def get_cves_for_service(
        self, service: str, version: Optional[str] = None
    ) -> list[CVEEntry]:
        """Return CVEs whose affected products match *service* (and optionally *version*)."""
        service_lower = service.lower()
        matches: list[CVEEntry] = []
        for entry in self._db.values():
            for product in entry.affected_products:
                product_lower = product.lower()
                if service_lower in product_lower:
                    if version and version not in product_lower:
                        continue
                    matches.append(entry)
                    break
        return matches

    def get_critical_cves(self) -> list[CVEEntry]:
        """Return all CVEs with CRITICAL severity."""
        return [e for e in self._db.values() if e.severity == Severity.CRITICAL]

    def correlate_with_scan(self, scan_results: dict) -> list[CVEEntry]:
        """
        Match scan results against the CVE database.

        Expects *scan_results* to contain a ``services`` key with a list of
        dicts, each having at least ``name`` and optionally ``version``.

        Example::

            {
                "services": [
                    {"name": "apache", "version": "2.4.49"},
                    {"name": "openssh", "version": "8.9"},
                ]
            }
        """
        matched: list[CVEEntry] = []
        seen: set[str] = set()
        for svc in scan_results.get("services", []):
            name = svc.get("name", "")
            version = svc.get("version")
            for entry in self.get_cves_for_service(name, version):
                if entry.cve_id not in seen:
                    seen.add(entry.cve_id)
                    matched.append(entry)
        return matched

    def generate_advisory(self, cve_entries: list[CVEEntry]) -> str:
        """
        Produce a Markdown-formatted advisory from a list of CVE entries.
        """
        if not cve_entries:
            return "_No CVEs to report._"

        lines = [
            "# CVE Advisory Report",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total CVEs:** {len(cve_entries)}",
            "",
            "---",
            "",
        ]

        for entry in sorted(cve_entries, key=lambda e: e.cvss_score, reverse=True):
            exploit_badge = " ⚠️ **Exploit Available**" if entry.exploits_available else ""
            lines += [
                f"## {entry.cve_id} — {entry.severity.value} (CVSS {entry.cvss_score}){exploit_badge}",
                "",
                entry.description,
                "",
                f"**Affected Products:** {', '.join(entry.affected_products) or 'N/A'}",
                f"**Published:** {entry.published_date or 'Unknown'}",
                "",
            ]
            if entry.references:
                lines.append("**References:**")
                for ref in entry.references:
                    lines.append(f"- {ref}")
                lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)


# Module-level default instance, pre-loaded with common CVEs
cve_intelligence = CVEIntelligence(preload=True)
