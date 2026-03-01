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
