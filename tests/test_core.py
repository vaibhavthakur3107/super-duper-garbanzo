"""
Core tests for Cyber-Sentry AI.
Tests scope validation, notes manager, playbooks, LLM provider constants,
and CLI helpers – all without requiring live network access or an LLM.
"""

import json
import pytest
from pathlib import Path

from cyber_sentry.guardrails.scope_validator import validate_scope
from cyber_sentry.notes import NotesManager
from cyber_sentry.providers import (
    PROVIDER_OLLAMA,
    PROVIDER_OPENAI,
    PROVIDER_ANTHROPIC,
    PROVIDER_OPENROUTER,
    OPENROUTER_BASE_URL,
)
from cyber_sentry.cli import list_playbooks, load_playbook


# ── Scope Validator ───────────────────────────────────────────────────────────

class TestScopeValidator:
    """Tests for guardrails/scope_validator.py"""

    def test_authorized_example_com(self):
        assert validate_scope("example.com") is True

    def test_authorized_localhost(self):
        assert validate_scope("localhost") is True

    def test_authorized_loopback_ip(self):
        assert validate_scope("127.0.0.1") is True

    def test_authorized_private_10_net(self):
        assert validate_scope("10.0.0.1") is True

    def test_authorized_private_192_168(self):
        assert validate_scope("192.168.1.100") is True

    def test_denied_public_domain(self):
        assert validate_scope("google.com") is False

    def test_denied_evil_domain(self):
        assert validate_scope("evil.com") is False

    def test_empty_target_denied(self):
        assert validate_scope("") is False

    def test_strips_http_prefix(self):
        assert validate_scope("http://example.com") is True

    def test_strips_https_prefix(self):
        assert validate_scope("https://example.com/path") is True

    def test_strips_port(self):
        assert validate_scope("example.com:8080") is True


# ── Notes Manager ─────────────────────────────────────────────────────────────

class TestNotesManager:
    """Tests for notes.py"""

    @pytest.fixture
    def notes(self, tmp_path):
        return NotesManager(loot_dir=tmp_path)

    def test_add_note_finding(self, notes):
        note = notes.add_note("Found open port 22", category="finding", target="10.0.0.1")
        assert note["category"] == "finding"
        assert note["target"] == "10.0.0.1"
        assert "Found open port 22" in note["content"]

    def test_add_note_vulnerability(self, notes):
        note = notes.add_note("CVE-2024-0001 detected", category="vulnerability")
        assert note["category"] == "vulnerability"

    def test_add_note_credential(self, notes):
        note = notes.add_note("admin:admin", category="credential")
        assert note["category"] == "credential"

    def test_unknown_category_defaults_to_finding(self, notes):
        note = notes.add_note("Something", category="unknown_category")
        assert note["category"] == "finding"

    def test_get_notes_all(self, notes):
        notes.add_note("note1")
        notes.add_note("note2")
        assert len(notes.get_notes()) == 2

    def test_get_notes_filtered_by_category(self, notes):
        notes.add_note("vuln1", category="vulnerability")
        notes.add_note("find1", category="finding")
        vulns = notes.get_notes(category="vulnerability")
        assert len(vulns) == 1
        assert vulns[0]["content"] == "vuln1"

    def test_get_notes_filtered_by_target(self, notes):
        notes.add_note("note A", target="10.0.0.1")
        notes.add_note("note B", target="10.0.0.2")
        results = notes.get_notes(target="10.0.0.1")
        assert len(results) == 1
        assert results[0]["content"] == "note A"

    def test_notes_persisted_to_disk(self, tmp_path):
        notes = NotesManager(loot_dir=tmp_path)
        notes.add_note("persisted note")
        # Load fresh instance from same dir
        notes2 = NotesManager(loot_dir=tmp_path)
        assert len(notes2.get_notes()) == 1

    def test_generate_report_creates_file(self, notes, tmp_path):
        notes.add_note("CVE found", category="vulnerability", target="10.0.0.1")
        fake_results = [
            {
                "thought_trace": [
                    {
                        "node": "tool",
                        "action": "nmap_scan",
                        "thought": "Scanning",
                        "reasoning": "Need ports",
                        "observation": "22/tcp open ssh",
                    }
                ]
            }
        ]
        path = notes.generate_report(fake_results, target="10.0.0.1")
        assert path.exists()
        content = path.read_text()
        assert "Penetration Test Report" in content
        assert "10.0.0.1" in content
        assert "nmap_scan" in content


# ── Provider Constants ────────────────────────────────────────────────────────

class TestProviderConstants:
    """Sanity checks on LLM provider constants."""

    def test_ollama_constant(self):
        assert PROVIDER_OLLAMA == "ollama"

    def test_openai_constant(self):
        assert PROVIDER_OPENAI == "openai"

    def test_anthropic_constant(self):
        assert PROVIDER_ANTHROPIC == "anthropic"

    def test_openrouter_constant(self):
        assert PROVIDER_OPENROUTER == "openrouter"

    def test_openrouter_base_url(self):
        assert OPENROUTER_BASE_URL == "https://openrouter.ai/api/v1"


# ── Playbooks ─────────────────────────────────────────────────────────────────

class TestPlaybooks:
    """Tests for playbook discovery and loading."""

    def test_list_playbooks_non_empty(self):
        names = list_playbooks()
        assert len(names) > 0, "Expected at least one playbook"

    def test_expected_playbooks_present(self):
        names = list_playbooks()
        for expected in ["web_pentest", "network_audit", "recon", "ctf"]:
            assert expected in names, f"Playbook '{expected}' not found"

    def test_load_web_pentest(self):
        pb = load_playbook("web_pentest")
        assert pb is not None
        assert pb.get("name") == "web_pentest"

    def test_load_recon(self):
        pb = load_playbook("recon")
        assert pb is not None
        assert pb.get("category") == "reconnaissance"

    def test_load_missing_returns_none(self):
        assert load_playbook("does_not_exist") is None

    def test_playbook_has_description(self):
        for name in list_playbooks():
            pb = load_playbook(name)
            assert pb is not None
            assert pb.get("description"), f"Playbook '{name}' missing description"


# ── Network Tools Helpers ─────────────────────────────────────────────────────

class TestNetworkToolHelpers:
    """Tests for output parsers in network_tools.py"""

    def test_extract_ports(self):
        from cyber_sentry.tools.network_tools import extract_ports
        sample = "80/tcp   open  http\n443/tcp  open  https\n22/tcp   open  ssh"
        ports = extract_ports(sample)
        assert len(ports) == 3
        assert any(p["port"] == 80 and p["service"] == "http" for p in ports)

    def test_extract_ports_empty(self):
        from cyber_sentry.tools.network_tools import extract_ports
        assert extract_ports("No ports found") == []

    def test_extract_cves(self):
        from cyber_sentry.tools.network_tools import extract_cves
        sample = "[CVE-2024-1234] High severity\n[CVE-2023-5678] Medium\n[CVE-2024-1234] duplicate"
        cves = extract_cves(sample)
        assert "CVE-2024-1234" in cves
        assert "CVE-2023-5678" in cves
        assert len(cves) == 2  # deduped

    def test_extract_urls(self):
        from cyber_sentry.tools.network_tools import extract_urls
        sample = "/admin (Status: 200)\n/login (Status: 301)\n/secret (Status: 403)"
        urls = extract_urls(sample)
        paths = [u["path"] for u in urls]
        assert "/admin" in paths
        assert "/login" in paths
        assert "/secret" in paths

    def test_sanitize_command_blocks_rm_rf(self):
        from cyber_sentry.tools.network_tools import sanitize_command
        ok, err = sanitize_command("nmap -sV target; rm -rf /")
        assert ok is False
        assert "Dangerous" in err

    def test_sanitize_command_allows_nmap(self):
        from cyber_sentry.tools.network_tools import sanitize_command
        ok, err = sanitize_command("nmap -sV -sC -T4 example.com")
        assert ok is True
        assert err == ""

    def test_web_search_in_registry(self):
        from cyber_sentry.tools.network_tools import tool_registry
        names = [t["name"] for t in tool_registry.list_tools()]
        assert "web_search" in names


# ── MCP Client ────────────────────────────────────────────────────────────────

class TestMCPClient:
    """Tests for the MCP client (no actual MCP server required)."""

    @pytest.fixture
    def mcp(self, tmp_path):
        from cyber_sentry.mcp import MCPClient
        return MCPClient(config_path=tmp_path / "mcp_servers.json")

    def test_list_empty_initially(self, mcp):
        assert mcp.list_servers() == []

    def test_add_server(self, mcp):
        cfg = mcp.add_server("nmap", "npx", args=["-y", "gc-nmap-mcp"],
                             description="nmap MCP")
        assert cfg.name == "nmap"
        assert cfg.command == "npx"
        assert cfg.args == ["-y", "gc-nmap-mcp"]

    def test_list_after_add(self, mcp):
        mcp.add_server("nmap", "npx")
        servers = mcp.list_servers()
        assert len(servers) == 1
        assert servers[0]["name"] == "nmap"

    def test_get_server(self, mcp):
        mcp.add_server("burp", "java", args=["-jar", "burpsuite.jar"])
        cfg = mcp.get_server("burp")
        assert cfg is not None
        assert cfg.command == "java"

    def test_get_missing_server(self, mcp):
        assert mcp.get_server("does_not_exist") is None

    def test_remove_server(self, mcp):
        mcp.add_server("test", "echo")
        removed = mcp.remove_server("test")
        assert removed is True
        assert mcp.get_server("test") is None

    def test_remove_missing_returns_false(self, mcp):
        assert mcp.remove_server("nonexistent") is False

    def test_persisted_to_disk(self, tmp_path):
        from cyber_sentry.mcp import MCPClient
        mcp1 = MCPClient(config_path=tmp_path / "mcp.json")
        mcp1.add_server("nmap", "npx", description="test")
        # Load fresh instance
        mcp2 = MCPClient(config_path=tmp_path / "mcp.json")
        servers = mcp2.list_servers()
        assert len(servers) == 1
        assert servers[0]["description"] == "test"

    def test_test_unavailable_command(self, mcp):
        mcp.add_server("fake", "this_command_does_not_exist_9x7z")
        ok, msg = mcp.test_server("fake")
        assert ok is False
        assert "not found" in msg.lower()

    def test_test_missing_server(self, mcp):
        ok, msg = mcp.test_server("not_configured")
        assert ok is False

    def test_load_from_example_format(self, tmp_path):
        """Verify the example JSON format loads correctly."""
        import json
        from cyber_sentry.mcp import MCPClient
        config = {
            "mcpServers": {
                "nmap": {
                    "command": "npx",
                    "args": ["-y", "gc-nmap-mcp"],
                    "env": {"NMAP_PATH": "/usr/bin/nmap"},
                    "description": "nmap MCP server",
                }
            }
        }
        cfg_path = tmp_path / "mcp_servers.json"
        cfg_path.write_text(json.dumps(config))
        client = MCPClient(config_path=cfg_path)
        servers = client.list_servers()
        assert len(servers) == 1
        assert servers[0]["name"] == "nmap"
        assert servers[0]["args"] == ["-y", "gc-nmap-mcp"]


# ── Knowledge Base ────────────────────────────────────────────────────────────

class TestKnowledgeBase:
    """Tests for the knowledge module."""

    @pytest.fixture
    def kb(self, tmp_path):
        from cyber_sentry.knowledge import KnowledgeBase
        sources = tmp_path / "sources"
        sources.mkdir()
        (sources / "web.md").write_text("# Web Methodology\nAlways check OWASP Top 10.")
        (sources / "network.txt").write_text("Phase 1: Host Discovery\nnmap -sn target")
        return KnowledgeBase(sources_dir=sources)

    def test_list_sources(self, kb):
        names = kb.list_sources()
        assert "web" in names
        assert "network" in names

    def test_get_document(self, kb):
        doc = kb.get("web")
        assert doc is not None
        assert "OWASP" in doc

    def test_get_missing_returns_none(self, kb):
        assert kb.get("nonexistent") is None

    def test_get_context_all(self, kb):
        ctx = kb.get_context()
        assert "Web Methodology" in ctx
        assert "Host Discovery" in ctx

    def test_get_context_with_query(self, kb):
        ctx = kb.get_context("web")
        assert "OWASP" in ctx

    def test_get_context_empty_sources(self, tmp_path):
        from cyber_sentry.knowledge import KnowledgeBase
        kb = KnowledgeBase(sources_dir=tmp_path / "empty")
        assert kb.get_context() == ""

    def test_builtin_sources_loaded(self):
        """The built-in knowledge/sources/ directory should have at least one doc."""
        from cyber_sentry.knowledge import knowledge_base
        knowledge_base.reload()
        assert len(knowledge_base.list_sources()) >= 1


# ── Expanded Tool Arsenal (67 tools) ─────────────────────────────────────────

class TestExpandedToolArsenal:
    """Tests for the 67-tool arsenal added in the tool expansion."""

    @pytest.fixture
    def registry(self):
        from cyber_sentry.tools.network_tools import ToolRegistry
        return ToolRegistry()

    def _names(self, registry):
        return [t["name"] for t in registry.list_tools()]

    # -- total count --
    def test_tool_count_at_least_60(self, registry):
        assert len(registry.list_tools()) >= 60

    # -- Network reconnaissance --
    def test_rustscan_registered(self, registry):
        assert "rustscan" in self._names(registry)

    def test_masscan_registered(self, registry):
        assert "masscan" in self._names(registry)

    def test_amass_registered(self, registry):
        assert "amass_enum" in self._names(registry)

    def test_subfinder_registered(self, registry):
        assert "subfinder" in self._names(registry)

    def test_theharvester_registered(self, registry):
        assert "theharvester" in self._names(registry)

    def test_enum4linux_registered(self, registry):
        assert "enum4linux" in self._names(registry)

    def test_smbmap_registered(self, registry):
        assert "smbmap" in self._names(registry)

    # -- Web application --
    def test_feroxbuster_registered(self, registry):
        assert "feroxbuster" in self._names(registry)

    def test_ffuf_registered(self, registry):
        assert "ffuf" in self._names(registry)

    def test_dalfox_registered(self, registry):
        assert "dalfox" in self._names(registry)

    def test_wpscan_registered(self, registry):
        assert "wpscan" in self._names(registry)

    def test_wafw00f_registered(self, registry):
        assert "wafw00f" in self._names(registry)

    def test_whatweb_registered(self, registry):
        assert "whatweb" in self._names(registry)

    def test_testssl_registered(self, registry):
        assert "testssl" in self._names(registry)

    def test_commix_registered(self, registry):
        assert "commix" in self._names(registry)

    def test_tplmap_registered(self, registry):
        assert "tplmap" in self._names(registry)

    # -- Authentication --
    def test_hydra_registered(self, registry):
        assert "hydra" in self._names(registry)

    def test_hashcat_registered(self, registry):
        assert "hashcat" in self._names(registry)

    def test_john_registered(self, registry):
        assert "john_crack" in self._names(registry)

    # -- OSINT --
    def test_sherlock_registered(self, registry):
        assert "sherlock" in self._names(registry)

    def test_trufflehog_registered(self, registry):
        assert "trufflehog" in self._names(registry)

    def test_shodan_registered(self, registry):
        assert "shodan_search" in self._names(registry)

    # -- Forensics / Binary --
    def test_volatility3_registered(self, registry):
        assert "volatility3" in self._names(registry)

    def test_exiftool_registered(self, registry):
        assert "exiftool" in self._names(registry)

    def test_radare2_registered(self, registry):
        assert "radare2" in self._names(registry)

    def test_checksec_registered(self, registry):
        assert "checksec" in self._names(registry)

    # -- Cloud --
    def test_trivy_registered(self, registry):
        assert "trivy_scan" in self._names(registry)

    def test_prowler_registered(self, registry):
        assert "prowler" in self._names(registry)

    def test_kube_hunter_registered(self, registry):
        assert "kube_hunter" in self._names(registry)

    # -- Categories present --
    def test_authentication_category_exists(self, registry):
        cats = {t["category"] for t in registry.list_tools()}
        assert "authentication" in cats

    def test_osint_category_exists(self, registry):
        cats = {t["category"] for t in registry.list_tools()}
        assert "osint" in cats

    def test_forensics_category_exists(self, registry):
        cats = {t["category"] for t in registry.list_tools()}
        assert "forensics" in cats

    def test_binary_category_exists(self, registry):
        cats = {t["category"] for t in registry.list_tools()}
        assert "binary" in cats

    def test_cloud_category_exists(self, registry):
        cats = {t["category"] for t in registry.list_tools()}
        assert "cloud" in cats


# ── New Playbooks ─────────────────────────────────────────────────────────────

class TestNewPlaybooks:
    """Tests for the 3 new playbooks added in the tool expansion."""

    def test_bugbounty_discoverable(self):
        assert "bugbounty" in list_playbooks()

    def test_cloud_security_discoverable(self):
        assert "cloud_security" in list_playbooks()

    def test_binary_forensics_discoverable(self):
        assert "binary_forensics" in list_playbooks()

    def test_bugbounty_loads(self):
        pb = load_playbook("bugbounty")
        assert pb is not None
        assert pb.get("name") == "bugbounty"

    def test_cloud_security_loads(self):
        pb = load_playbook("cloud_security")
        assert pb is not None
        assert pb.get("category") == "cloud"

    def test_binary_forensics_loads(self):
        pb = load_playbook("binary_forensics")
        assert pb is not None
        assert pb.get("category") == "forensics"

    def test_total_playbook_count_at_least_7(self):
        assert len(list_playbooks()) >= 7


# ── New Knowledge Sources ─────────────────────────────────────────────────────

class TestNewKnowledgeSources:
    """Tests for the 3 new knowledge source files."""

    def test_builtin_sources_at_least_5(self):
        from cyber_sentry.knowledge import KnowledgeBase
        kb = KnowledgeBase()
        assert len(kb.list_sources()) >= 5

    def test_osint_source_loaded(self):
        from cyber_sentry.knowledge import KnowledgeBase
        kb = KnowledgeBase()
        assert "osint_bugbounty_methodology" in kb.list_sources()

    def test_cloud_source_loaded(self):
        from cyber_sentry.knowledge import KnowledgeBase
        kb = KnowledgeBase()
        assert "cloud_security_methodology" in kb.list_sources()

    def test_binary_source_loaded(self):
        from cyber_sentry.knowledge import KnowledgeBase
        kb = KnowledgeBase()
        assert "binary_forensics_methodology" in kb.list_sources()

    def test_osint_context_contains_amass(self):
        from cyber_sentry.knowledge import KnowledgeBase
        kb = KnowledgeBase()
        ctx = kb.get_context("osint subdomain")
        assert "amass" in ctx.lower()

    def test_cloud_context_contains_aws(self):
        from cyber_sentry.knowledge import KnowledgeBase
        kb = KnowledgeBase()
        ctx = kb.get_context("aws cloud")
        assert "aws" in ctx.lower()

    def test_binary_context_contains_gdb(self):
        from cyber_sentry.knowledge import KnowledgeBase
        kb = KnowledgeBase()
        ctx = kb.get_context("gdb binary")
        assert "gdb" in ctx.lower()
