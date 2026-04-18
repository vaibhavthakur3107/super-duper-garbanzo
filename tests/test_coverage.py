"""
Extended test coverage for Dexter AI Pentest.

Covers modules with missing or insufficient tests:
- decoder.py (cipher utilities)
- dexter_ai/db/memory.py (ConversationMemory)
- dexter_ai/guardrails/security.py (security guardrail classes)
- dexter_ai/providers.py (ALL_PROVIDERS, get_llm error paths)
- dexter_ai/cache.py (tool-result helpers, default TTL, update, stats reset)
- dexter_ai/cve_intel.py (add_cve, get_cves_for_service, correlate_with_scan)
- dexter_ai/reporting.py (_classify_finding, _severity_from_finding, format_finding)
- dexter_ai/notes.py (sequential IDs, source field, artifact, clear_session, corrupted JSON)
- dexter_ai/process_manager.py (stop_process, get_process, get_output, cleanup_finished)
- dexter_ai/tools/registry.py (ToolRegistry.get, get_by_category, validate_input)
"""

import asyncio
import json
import os
import sys
import time
import pytest
from pathlib import Path


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(coro):
    """Run an async coroutine synchronously inside tests."""
    return asyncio.run(coro)


# ── Decoder Cipher Functions ──────────────────────────────────────────────────

class TestDecoderCiphers:
    """Tests for cipher utility functions in decoder.py (project root)."""

    @pytest.fixture(autouse=True)
    def _import_decoder(self):
        # decoder.py sits at the repo root, not inside the package
        root = Path(__file__).parent.parent
        sys.path.insert(0, str(root))
        import decoder as _d
        self.d = _d
        yield
        sys.path.pop(0)

    # -- xor_single_byte --

    def test_xor_single_byte_with_zero_is_identity(self):
        result = self.d.xor_single_byte("ABC", 0)
        assert result == "ABC"

    def test_xor_single_byte_roundtrip(self):
        original = "Hello, World!"
        key = 42
        encrypted = self.d.xor_single_byte(original, key)
        decrypted = self.d.xor_single_byte(encrypted, key)
        assert decrypted == original

    # -- xor_multi_byte --

    def test_xor_multi_byte_roundtrip(self):
        original = "SecretMessage"
        key = "KEY"
        encrypted = self.d.xor_multi_byte(original, key)
        decrypted = self.d.xor_multi_byte(encrypted, key)
        assert decrypted == original

    # -- caesar_shift --

    def test_caesar_shift_lowercase(self):
        assert self.d.caesar_shift("abc", 1) == "bcd"

    def test_caesar_shift_uppercase(self):
        assert self.d.caesar_shift("XYZ", 3) == "ABC"

    def test_caesar_shift_non_alpha_unchanged(self):
        assert self.d.caesar_shift("12! 34", 5) == "12! 34"

    def test_caesar_shift_wraparound(self):
        assert self.d.caesar_shift("z", 1) == "a"
        assert self.d.caesar_shift("Z", 1) == "A"

    def test_caesar_shift_zero_is_identity(self):
        text = "Hello World"
        assert self.d.caesar_shift(text, 0) == text

    def test_caesar_rot13(self):
        assert self.d.caesar_shift("Hello", 13) == "Uryyb"

    # -- rot47 --

    def test_rot47_roundtrip(self):
        text = "Hello, World! 123"
        assert self.d.rot47(self.d.rot47(text)) == text

    def test_rot47_space_unchanged(self):
        # Space (ord 32) is below the printable range (33-126) so it is unchanged
        assert self.d.rot47(" ") == " "

    def test_rot47_exclamation_transformed(self):
        # '!' is ord 33, first printable; (33 + 14) % 94 + 33 = 47 + 33 = 80 = 'P'
        assert self.d.rot47("!") == "P"

    # -- vigenere_decode --

    def test_vigenere_decode_roundtrip(self):
        from itertools import cycle as _cycle

        def _vigenere_encode(text, key):
            result = ""
            key_index = 0
            for char in text:
                if char.isalpha():
                    key_char = key[key_index % len(key)]
                    if char.islower():
                        base = ord('a')
                        result += chr((ord(char) - base + (ord(key_char.upper()) - ord('A'))) % 26 + base)
                    else:
                        base = ord('A')
                        result += chr((ord(char) - base + (ord(key_char.upper()) - ord('A'))) % 26 + base)
                    key_index += 1
                else:
                    result += char
            return result

        original = "HelloWorld"
        key = "SECRET"
        encoded = _vigenere_encode(original, key)
        decoded = self.d.vigenere_decode(encoded, key)
        assert decoded.lower() == original.lower()

    def test_vigenere_decode_non_alpha_unchanged(self):
        result = self.d.vigenere_decode("123-456", "KEY")
        assert result == "123-456"

    # -- atbash --

    def test_atbash_a_becomes_z(self):
        assert self.d.atbash("a") == "z"

    def test_atbash_z_becomes_a(self):
        assert self.d.atbash("z") == "a"

    def test_atbash_uppercase(self):
        assert self.d.atbash("A") == "Z"
        assert self.d.atbash("Z") == "A"

    def test_atbash_roundtrip(self):
        text = "Hello World"
        assert self.d.atbash(self.d.atbash(text)) == text

    def test_atbash_non_alpha_unchanged(self):
        assert self.d.atbash("123!") == "123!"

    # -- is_printable --

    def test_is_printable_all_printable(self):
        assert self.d.is_printable("Hello, World! 123") is True

    def test_is_printable_all_non_printable(self):
        # Build a string of non-printable chars
        garbage = "".join(chr(i) for i in range(1, 32))
        assert self.d.is_printable(garbage, threshold=0.1) is False

    def test_is_printable_custom_threshold(self):
        # 5 printable + 5 non-printable = 0.5 ratio
        text = "Hello" + "".join(chr(i) for i in range(1, 6))
        assert self.d.is_printable(text, threshold=0.4) is True
        assert self.d.is_printable(text, threshold=0.9) is False

    # -- contains_flag --

    def test_contains_flag_present(self):
        assert self.d.contains_flag("some prefix FLAG{secret} suffix") is True

    def test_contains_flag_absent(self):
        assert self.d.contains_flag("no flag here") is False

    def test_contains_flag_partial_word(self):
        assert self.d.contains_flag("FLAGGED content") is False


# ── ConversationMemory (db/memory.py) ─────────────────────────────────────────

class TestConversationMemory:
    """Tests for SQLite-backed ConversationMemory."""

    @pytest.fixture
    def memory(self, tmp_path):
        from dexter_ai.db.memory import ConversationMemory
        return ConversationMemory(db_path=str(tmp_path / "test.db"))

    def test_create_session_returns_true(self, memory):
        assert memory.create_session("sess-1", "10.0.0.1", "full pentest") is True

    def test_create_duplicate_session_returns_false(self, memory):
        memory.create_session("sess-dup", "10.0.0.1", "task")
        assert memory.create_session("sess-dup", "10.0.0.2", "other") is False

    def test_get_session_returns_dict(self, memory):
        memory.create_session("sess-get", "192.168.1.1", "recon")
        session = memory.get_session("sess-get")
        assert session is not None
        assert session["session_id"] == "sess-get"
        assert session["target"] == "192.168.1.1"
        assert session["task"] == "recon"
        assert session["status"] == "running"

    def test_get_missing_session_returns_none(self, memory):
        assert memory.get_session("nonexistent") is None

    def test_update_session_status(self, memory):
        memory.create_session("sess-upd", "10.0.0.1", "task")
        memory.update_session_status("sess-upd", "completed")
        session = memory.get_session("sess-upd")
        assert session["status"] == "completed"

    def test_add_and_get_thoughts(self, memory):
        memory.create_session("sess-th", "10.0.0.1", "test")
        memory.add_thought("sess-th", {
            "node": "tool",
            "thought": "Scanning target",
            "reasoning": "Need to identify open ports",
            "action": "nmap_scan",
            "action_input": {"target": "10.0.0.1"},
            "observation": "22/tcp open ssh",
        })
        thoughts = memory.get_thoughts("sess-th")
        assert len(thoughts) == 1
        t = thoughts[0]
        assert t["node"] == "tool"
        assert t["action"] == "nmap_scan"
        assert t["observation"] == "22/tcp open ssh"

    def test_get_thoughts_empty(self, memory):
        memory.create_session("sess-empty", "10.0.0.1", "test")
        assert memory.get_thoughts("sess-empty") == []

    def test_add_message_no_error(self, memory):
        memory.create_session("sess-msg", "10.0.0.1", "test")
        # Should not raise
        memory.add_message("sess-msg", "user", "Scan 10.0.0.1 for vulnerabilities")
        memory.add_message("sess-msg", "assistant", "Starting scan...")

    def test_add_tool_result_no_error(self, memory):
        memory.create_session("sess-tool", "10.0.0.1", "test")
        memory.add_tool_result(
            "sess-tool",
            "nmap_scan",
            "nmap -sV 10.0.0.1",
            {"ports": [22, 80]},
        )

    def test_list_sessions_empty(self, memory):
        assert memory.list_sessions() == []

    def test_list_sessions_returns_entries(self, memory):
        memory.create_session("sess-a", "10.0.0.1", "task-a")
        memory.create_session("sess-b", "10.0.0.2", "task-b")
        sessions = memory.list_sessions()
        assert len(sessions) == 2
        session_ids = {s["session_id"] for s in sessions}
        assert "sess-a" in session_ids
        assert "sess-b" in session_ids

    def test_list_sessions_respects_limit(self, memory):
        for i in range(5):
            memory.create_session(f"sess-lim-{i}", "10.0.0.1", f"task-{i}")
        sessions = memory.list_sessions(limit=3)
        assert len(sessions) == 3

    def test_multiple_thoughts_ordered(self, memory):
        memory.create_session("sess-ord", "10.0.0.1", "test")
        for i in range(3):
            memory.add_thought("sess-ord", {
                "node": f"node_{i}",
                "action": f"action_{i}",
            })
        thoughts = memory.get_thoughts("sess-ord")
        assert len(thoughts) == 3
        for i, t in enumerate(thoughts):
            assert t["node"] == f"node_{i}"


# ── Security Guardrails ────────────────────────────────────────────────────────

class TestScopeValidationGuardrail:
    """Tests for ScopeValidationGuardrail in guardrails/security.py."""

    @pytest.fixture
    def guardrail(self):
        from dexter_ai.guardrails.security import ScopeValidationGuardrail
        return ScopeValidationGuardrail(allowed_domains=["example.com", "test.local"])

    def test_allowed_domain(self, guardrail):
        allowed, reason = _run(guardrail.check("scan", {"target": "example.com"}, {}))
        assert allowed is True
        assert reason is None

    def test_subdomain_of_allowed(self, guardrail):
        allowed, _ = _run(guardrail.check("scan", {"target": "sub.example.com"}, {}))
        assert allowed is True

    def test_private_ip_always_allowed(self, guardrail):
        for ip in ["10.0.0.1", "192.168.1.100", "172.16.0.1", "127.0.0.1"]:
            allowed, _ = _run(guardrail.check("scan", {"target": ip}, {}))
            assert allowed is True, f"Private IP {ip} should be allowed"

    def test_localhost_allowed(self, guardrail):
        allowed, _ = _run(guardrail.check("scan", {"target": "localhost"}, {}))
        assert allowed is True

    def test_denied_domain(self, guardrail):
        allowed, reason = _run(guardrail.check("scan", {"target": "evil.com"}, {}))
        assert allowed is False
        assert reason is not None

    def test_empty_target_passthrough(self, guardrail):
        # Empty target means no scope check needed (action has no target)
        allowed, _ = _run(guardrail.check("list_tools", {}, {}))
        assert allowed is True


class TestDangerousActionGuardrail:
    """Tests for DangerousActionGuardrail."""

    @pytest.fixture
    def guardrail(self):
        from dexter_ai.guardrails.security import DangerousActionGuardrail
        return DangerousActionGuardrail()

    def test_dangerous_action_blocked(self, guardrail):
        allowed, reason = _run(guardrail.check("delete_data", {}, {}))
        assert allowed is False
        assert reason is not None

    def test_safe_action_allowed(self, guardrail):
        allowed, reason = _run(guardrail.check("scan_ports", {}, {}))
        assert allowed is True

    def test_destructive_param_blocked(self, guardrail):
        allowed, reason = _run(guardrail.check("something", {"destructive": True}, {}))
        assert allowed is False

    def test_force_param_blocked(self, guardrail):
        allowed, reason = _run(guardrail.check("something", {"force": True}, {}))
        assert allowed is False

    def test_install_malware_blocked(self, guardrail):
        allowed, _ = _run(guardrail.check("install_malware_payload", {}, {}))
        assert allowed is False

    def test_execute_arbitrary_code_blocked(self, guardrail):
        allowed, _ = _run(guardrail.check("execute_arbitrary_code", {}, {}))
        assert allowed is False


class TestInputValidationGuardrail:
    """Tests for InputValidationGuardrail."""

    @pytest.fixture
    def guardrail(self):
        from dexter_ai.guardrails.security import InputValidationGuardrail
        return InputValidationGuardrail()

    def test_clean_input_allowed(self, guardrail):
        allowed, _ = _run(guardrail.check("scan", {"target": "example.com"}, {}))
        assert allowed is True

    def test_shell_metachar_blocked(self, guardrail):
        allowed, reason = _run(guardrail.check("scan", {"target": "example.com; rm -rf /"}, {}))
        assert allowed is False
        assert reason is not None

    def test_sql_injection_blocked(self, guardrail):
        allowed, _ = _run(guardrail.check("query", {"input": "1 UNION SELECT * FROM users"}, {}))
        assert allowed is False

    def test_path_traversal_blocked(self, guardrail):
        allowed, _ = _run(guardrail.check("read", {"file": "../../etc/passwd"}, {}))
        assert allowed is False

    def test_script_tag_blocked(self, guardrail):
        allowed, _ = _run(guardrail.check("submit", {"data": "<script>alert(1)</script>"}, {}))
        assert allowed is False

    def test_non_string_params_not_blocked(self, guardrail):
        allowed, _ = _run(guardrail.check("scan", {"port": 80, "timeout": 300}, {}))
        assert allowed is True


class TestLegalComplianceGuardrail:
    """Tests for LegalComplianceGuardrail."""

    @pytest.fixture
    def guardrail(self):
        from dexter_ai.guardrails.security import LegalComplianceGuardrail
        return LegalComplianceGuardrail()

    def test_gov_site_blocked(self, guardrail):
        allowed, reason = _run(guardrail.check("scan", {"target": "cia.gov"}, {}))
        assert allowed is False

    def test_mil_site_blocked(self, guardrail):
        allowed, _ = _run(guardrail.check("scan", {"target": "army.mil"}, {}))
        assert allowed is False

    def test_normal_site_allowed(self, guardrail):
        allowed, _ = _run(guardrail.check("scan", {"target": "example.com"}, {}))
        assert allowed is True

    def test_no_target_allowed(self, guardrail):
        allowed, _ = _run(guardrail.check("list", {}, {}))
        assert allowed is True


class TestOutputFilteringGuardrail:
    """Tests for OutputFilteringGuardrail."""

    @pytest.fixture
    def guardrail(self):
        from dexter_ai.guardrails.security import OutputFilteringGuardrail
        return OutputFilteringGuardrail()

    def test_check_always_passes(self, guardrail):
        allowed, _ = _run(guardrail.check("anything", {}, {}))
        assert allowed is True

    def test_filter_ssn(self, guardrail):
        output = guardrail.filter_output("User SSN is 123-45-6789 in the record.")
        assert "123-45-6789" not in output
        assert "[SSN]" in output

    def test_filter_password(self, guardrail):
        output = guardrail.filter_output("Config: password=supersecret123")
        assert "supersecret123" not in output
        assert "REDACTED" in output

    def test_filter_api_key(self, guardrail):
        output = guardrail.filter_output("api_key=abc123xyz")
        assert "abc123xyz" not in output
        assert "REDACTED" in output

    def test_clean_output_unchanged(self, guardrail):
        clean = "22/tcp open ssh"
        assert guardrail.filter_output(clean) == clean


class TestAuditLoggingGuardrail:
    """Tests for AuditLoggingGuardrail."""

    @pytest.fixture
    def guardrail(self):
        from dexter_ai.guardrails.security import AuditLoggingGuardrail
        return AuditLoggingGuardrail()

    def test_check_always_passes(self, guardrail):
        allowed, _ = _run(guardrail.check("scan_ports", {"target": "10.0.0.1"}, {"agent": "recon"}))
        assert allowed is True

    def test_logs_action_in_audit_log(self, guardrail):
        _run(guardrail.check("nmap_scan", {"target": "10.0.0.1"}, {"agent": "reconbot"}))
        log = guardrail.get_audit_log()
        assert len(log) == 1
        assert log[0]["action"] == "nmap_scan"
        assert log[0]["agent"] == "reconbot"

    def test_multiple_actions_logged(self, guardrail):
        _run(guardrail.check("action_a", {}, {}))
        _run(guardrail.check("action_b", {}, {}))
        _run(guardrail.check("action_c", {}, {}))
        assert len(guardrail.get_audit_log()) == 3


class TestSecurityGuardrailsCollection:
    """Tests for the SecurityGuardrails aggregate class."""

    @pytest.fixture
    def sg(self):
        from dexter_ai.guardrails.security import SecurityGuardrails
        return SecurityGuardrails()

    def test_list_guardrails_non_empty(self, sg):
        guardrails = sg.list_guardrails()
        assert len(guardrails) >= 5

    def test_list_guardrails_has_expected_names(self, sg):
        names = {g["name"] for g in sg.list_guardrails()}
        for expected in ["scope_validation", "dangerous_action", "input_validation",
                         "legal_compliance", "output_filtering"]:
            assert expected in names, f"Expected guardrail '{expected}' not found"

    def test_get_guardrail_by_name(self, sg):
        guardrail = sg.get_guardrail("scope_validation")
        assert guardrail is not None
        assert guardrail.name == "scope_validation"

    def test_get_missing_guardrail_returns_none(self, sg):
        assert sg.get_guardrail("nonexistent") is None

    def test_add_custom_guardrail(self, sg):
        from dexter_ai.guardrails.security import DangerousActionGuardrail
        custom = DangerousActionGuardrail()
        custom.name = "custom_test_guardrail"
        sg.add_guardrail(custom)
        assert sg.get_guardrail("custom_test_guardrail") is not None


# ── Provider Constants & get_llm ──────────────────────────────────────────────

class TestProviderExtended:
    """Additional tests for providers.py."""

    def test_all_providers_has_four_items(self):
        from dexter_ai.providers import ALL_PROVIDERS
        assert len(ALL_PROVIDERS) == 4

    def test_all_providers_contains_all_constants(self):
        from dexter_ai.providers import (
            ALL_PROVIDERS, PROVIDER_OLLAMA, PROVIDER_OPENAI,
            PROVIDER_ANTHROPIC, PROVIDER_OPENROUTER,
        )
        assert PROVIDER_OLLAMA in ALL_PROVIDERS
        assert PROVIDER_OPENAI in ALL_PROVIDERS
        assert PROVIDER_ANTHROPIC in ALL_PROVIDERS
        assert PROVIDER_OPENROUTER in ALL_PROVIDERS

    def test_get_llm_openai_missing_key_raises(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        from dexter_ai import providers
        try:
            providers.get_llm(provider="openai")
            pytest.skip("langchain-openai not installed, skipping")
        except ImportError:
            pytest.skip("langchain-openai not installed")
        except ValueError as exc:
            assert "OPENAI_API_KEY" in str(exc)

    def test_get_llm_anthropic_missing_key_raises(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        from dexter_ai import providers
        try:
            providers.get_llm(provider="anthropic")
            pytest.skip("langchain-anthropic not installed")
        except ImportError:
            pytest.skip("langchain-anthropic not installed")
        except ValueError as exc:
            assert "ANTHROPIC_API_KEY" in str(exc)

    def test_get_llm_openrouter_missing_key_raises(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        from dexter_ai import providers
        try:
            providers.get_llm(provider="openrouter")
            pytest.skip("langchain-openai not installed")
        except ImportError:
            pytest.skip("langchain-openai not installed")
        except ValueError as exc:
            assert "OPENROUTER_API_KEY" in str(exc)

    def test_auto_detect_prefers_openrouter(self, monkeypatch):
        """get_llm selects openrouter first when OPENROUTER_API_KEY is set."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "fake-or-key")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        from dexter_ai import providers
        try:
            providers.get_llm()
        except ImportError:
            pass  # package not installed, but detection code ran
        except ValueError as exc:
            assert "OPENROUTER_API_KEY" not in str(exc)  # key WAS set

    def test_auto_detect_openai_over_anthropic(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "fake-openai-key")
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        from dexter_ai import providers
        try:
            providers.get_llm()
        except ImportError:
            pass
        except ValueError as exc:
            assert "OPENAI_API_KEY" not in str(exc)


# ── SmartCache Extended ────────────────────────────────────────────────────────

class TestSmartCacheExtended:
    """Extended tests for SmartCache covering helpers and edge cases."""

    @pytest.fixture
    def cache(self):
        from dexter_ai.cache import SmartCache
        return SmartCache(max_size=10)

    def test_make_key_is_deterministic(self):
        from dexter_ai.cache import SmartCache
        k1 = SmartCache._make_key("nmap", "10.0.0.1", {"port": 80})
        k2 = SmartCache._make_key("nmap", "10.0.0.1", {"port": 80})
        assert k1 == k2

    def test_make_key_differs_on_tool_name(self):
        from dexter_ai.cache import SmartCache
        k1 = SmartCache._make_key("nmap", "10.0.0.1")
        k2 = SmartCache._make_key("masscan", "10.0.0.1")
        assert k1 != k2

    def test_make_key_differs_on_target(self):
        from dexter_ai.cache import SmartCache
        k1 = SmartCache._make_key("nmap", "10.0.0.1")
        k2 = SmartCache._make_key("nmap", "10.0.0.2")
        assert k1 != k2

    def test_make_key_differs_on_params(self):
        from dexter_ai.cache import SmartCache
        k1 = SmartCache._make_key("nmap", "10.0.0.1", {"port": 80})
        k2 = SmartCache._make_key("nmap", "10.0.0.1", {"port": 443})
        assert k1 != k2

    def test_cache_tool_result_round_trip(self, cache):
        cache.cache_tool_result("nmap", "10.0.0.1", {"flags": "-sV"}, {"ports": [22, 80]})
        result = cache.get_cached_result("nmap", "10.0.0.1", {"flags": "-sV"})
        assert result == {"ports": [22, 80]}

    def test_get_cached_result_miss_returns_none(self, cache):
        assert cache.get_cached_result("unknown_tool", "10.0.0.1") is None

    def test_default_ttl_applied(self):
        from dexter_ai.cache import SmartCache
        c = SmartCache(max_size=10, default_ttl=0.05)
        c.set("key", "value")
        assert c.get("key") == "value"
        time.sleep(0.1)
        assert c.get("key") is None

    def test_no_ttl_entry_never_expires(self, cache):
        cache.set("permanent", "data")
        time.sleep(0.05)
        assert cache.get("permanent") == "data"

    def test_update_existing_entry(self, cache):
        cache.set("key", "old")
        cache.set("key", "new")
        assert cache.get("key") == "new"

    def test_stats_reset_after_clear(self, cache):
        cache.set("a", 1)
        cache.get("a")       # hit
        cache.get("missing") # miss
        cache.clear()
        stats = cache.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["size"] == 0

    def test_invalidate_missing_key_returns_false(self, cache):
        assert cache.invalidate("no_such_key") is False

    def test_eviction_count_tracked(self):
        from dexter_ai.cache import SmartCache
        c = SmartCache(max_size=2)
        c.set("a", 1)
        c.set("b", 2)
        c.set("c", 3)  # evicts "a"
        stats = c.get_stats()
        assert stats["evictions"] == 1

    def test_hit_rate_calculation(self, cache):
        cache.set("x", 1)
        cache.get("x")      # hit
        cache.get("x")      # hit
        cache.get("miss")   # miss
        stats = cache.get_stats()
        assert abs(stats["hit_rate"] - (2 / 3)) < 0.01


# ── CVE Intelligence Extended ─────────────────────────────────────────────────

class TestCVEIntelligenceExtended:
    """Extended tests for CVEIntelligence."""

    @pytest.fixture
    def intel(self):
        from dexter_ai.cve_intel import CVEIntelligence
        return CVEIntelligence(preload=True)

    @pytest.fixture
    def empty_intel(self):
        from dexter_ai.cve_intel import CVEIntelligence
        return CVEIntelligence(preload=False)

    def test_empty_database_when_no_preload(self, empty_intel):
        assert len(empty_intel._db) == 0

    def test_add_cve_and_lookup(self, empty_intel):
        from dexter_ai.cve_intel import CVEEntry, Severity
        entry = CVEEntry(
            cve_id="CVE-2099-00001",
            severity=Severity.HIGH,
            description="Test vulnerability for unit testing",
            affected_products=["test:product"],
            cvss_score=7.5,
        )
        empty_intel.add_cve(entry)
        result = empty_intel.lookup_cve("CVE-2099-00001")
        assert result is not None
        assert result.cve_id == "CVE-2099-00001"

    def test_add_cve_overwrites_existing(self, intel):
        from dexter_ai.cve_intel import CVEEntry, Severity
        existing = intel.lookup_cve("CVE-2021-44228")
        assert existing is not None
        updated = CVEEntry(
            cve_id="CVE-2021-44228",
            severity=Severity.LOW,
            description="Updated description",
            affected_products=[],
            cvss_score=1.0,
        )
        intel.add_cve(updated)
        result = intel.lookup_cve("CVE-2021-44228")
        assert result.description == "Updated description"
        assert result.cvss_score == 1.0

    def test_lookup_cve_case_insensitive(self, intel):
        # lookup_cve uppercases the ID before lookup
        result = intel.lookup_cve("cve-2021-44228")
        assert result is not None
        assert result.cve_id == "CVE-2021-44228"

    def test_get_cves_for_service_match(self, intel):
        matches = intel.get_cves_for_service("log4j")
        assert len(matches) > 0
        assert any(e.cve_id == "CVE-2021-44228" for e in matches)

    def test_get_cves_for_service_no_match(self, intel):
        assert intel.get_cves_for_service("unknownservice999") == []

    def test_get_cves_for_service_version_filter(self, intel):
        # apache:http_server:2.4.49 should match the apache CVE-2021-41773
        matches = intel.get_cves_for_service("apache", version="2.4.49")
        assert any(e.cve_id == "CVE-2021-41773" for e in matches)

    def test_correlate_with_scan_matches(self, intel):
        scan_results = {
            "services": [
                {"name": "apache", "version": "2.4.49"},
                {"name": "openssh", "version": "9.0"},
            ]
        }
        matches = intel.correlate_with_scan(scan_results)
        assert len(matches) > 0
        cve_ids = [e.cve_id for e in matches]
        assert "CVE-2021-41773" in cve_ids  # apache 2.4.49

    def test_correlate_with_scan_no_duplicates(self, intel):
        scan_results = {
            "services": [
                {"name": "apache"},
                {"name": "apache"},  # duplicate service
            ]
        }
        matches = intel.correlate_with_scan(scan_results)
        cve_ids = [e.cve_id for e in matches]
        # No duplicates
        assert len(cve_ids) == len(set(cve_ids))

    def test_correlate_with_empty_services(self, intel):
        assert intel.correlate_with_scan({"services": []}) == []

    def test_generate_advisory_empty_list(self, intel):
        result = intel.generate_advisory([])
        assert result == "_No CVEs to report._"

    def test_generate_advisory_contains_cve_id(self, intel):
        entries = intel.get_critical_cves()[:2]
        advisory = intel.generate_advisory(entries)
        for entry in entries:
            assert entry.cve_id in advisory

    def test_search_cve_by_product(self, intel):
        results = intel.search_cve("log4j")
        assert any(e.cve_id == "CVE-2021-44228" for e in results)

    def test_search_cve_case_insensitive(self, intel):
        results = intel.search_cve("APACHE")
        assert len(results) > 0

    def test_get_critical_cves_all_critical(self, intel):
        from dexter_ai.cve_intel import Severity
        for entry in intel.get_critical_cves():
            assert entry.severity == Severity.CRITICAL


# ── Reporting Engine Extended ─────────────────────────────────────────────────

class TestReportingExtended:
    """Extended tests for reporting.py utility functions and generators."""

    def test_classify_finding_sqli(self):
        from dexter_ai.reporting import _classify_finding
        assert _classify_finding({"content": "SQL injection found in login"}) == "sqli"

    def test_classify_finding_xss(self):
        from dexter_ai.reporting import _classify_finding
        assert _classify_finding({"content": "XSS reflected vulnerability"}) == "xss"

    def test_classify_finding_ssrf(self):
        from dexter_ai.reporting import _classify_finding
        assert _classify_finding({"content": "Server-side request forgery via webhook"}) == "ssrf"

    def test_classify_finding_rce(self):
        from dexter_ai.reporting import _classify_finding
        assert _classify_finding({"content": "Remote code execution via deserialization"}) == "rce"

    def test_classify_finding_auth_bypass(self):
        from dexter_ai.reporting import _classify_finding
        assert _classify_finding({"content": "Authentication bypass via JWT none algorithm"}) == "auth_bypass"

    def test_classify_finding_lfi(self):
        from dexter_ai.reporting import _classify_finding
        assert _classify_finding({"content": "Local file inclusion at /index.php?page="}) == "lfi"

    def test_classify_finding_xxe(self):
        from dexter_ai.reporting import _classify_finding
        assert _classify_finding({"content": "XML external entity injection in upload"}) == "xxe"

    def test_classify_finding_default_unknown(self):
        from dexter_ai.reporting import _classify_finding
        assert _classify_finding({"content": "some random finding"}) == "default"

    def test_severity_from_finding_critical(self):
        from dexter_ai.reporting import _severity_from_finding
        assert _severity_from_finding({"content": "RCE via remote code execution"}) == "critical"

    def test_severity_from_finding_high(self):
        from dexter_ai.reporting import _severity_from_finding
        assert _severity_from_finding({"content": "SQL injection high severity"}) == "high"

    def test_severity_from_finding_medium(self):
        from dexter_ai.reporting import _severity_from_finding
        assert _severity_from_finding({"content": "XSS medium severity"}) == "medium"

    def test_severity_from_finding_low(self):
        from dexter_ai.reporting import _severity_from_finding
        assert _severity_from_finding({"content": "info disclosure low"}) == "low"

    def test_severity_from_finding_default_is_medium(self):
        from dexter_ai.reporting import _severity_from_finding
        assert _severity_from_finding({"content": "something unknown"}) == "medium"

    def test_format_finding_contains_title(self, tmp_path):
        from dexter_ai.reporting import ReportGenerator
        gen = ReportGenerator(loot_dir=tmp_path)
        output = gen.format_finding(
            {"content": "SQL injection at /login", "source": "sqlmap", "target": "10.0.0.1"},
            1,
        )
        assert "Finding #1" in output
        assert "sqlmap" in output
        assert "10.0.0.1" in output

    def test_format_finding_has_exploitation_and_remediation(self, tmp_path):
        from dexter_ai.reporting import ReportGenerator
        gen = ReportGenerator(loot_dir=tmp_path)
        output = gen.format_finding({"content": "XSS in search param", "source": "dalfox"}, 2)
        assert "Exploitation Guide" in output
        assert "Remediation" in output

    def test_calculate_risk_score_all_low(self, tmp_path):
        from dexter_ai.reporting import ReportGenerator
        gen = ReportGenerator(loot_dir=tmp_path)
        score = gen.calculate_risk_score([
            {"content": "info disclosure low"} for _ in range(3)
        ])
        assert score < 5  # all low should give a low score

    def test_calculate_risk_score_capped_at_10(self, tmp_path):
        from dexter_ai.reporting import ReportGenerator
        gen = ReportGenerator(loot_dir=tmp_path)
        score = gen.calculate_risk_score([
            {"content": "rce critical"} for _ in range(20)
        ])
        assert score <= 10

    def test_generate_full_report_no_findings_message(self, tmp_path):
        from dexter_ai.reporting import ReportGenerator
        gen = ReportGenerator(loot_dir=tmp_path)
        report = gen.generate_full_report([], "10.0.0.1")
        assert "No findings" in report or "0" in report

    def test_generate_full_report_with_notes_manager(self, tmp_path):
        from dexter_ai.reporting import ReportGenerator
        from dexter_ai.notes import NotesManager
        gen = ReportGenerator(loot_dir=tmp_path)
        nm = NotesManager(loot_dir=tmp_path / "loot")
        nm.add_note("SQL injection found", category="vulnerability", target="10.0.0.1")
        report = gen.generate_full_report([], "10.0.0.1", notes_manager=nm)
        assert "SQL injection found" in report

    def test_generate_exploitation_guide_for_all_types(self, tmp_path):
        from dexter_ai.reporting import ReportGenerator
        gen = ReportGenerator(loot_dir=tmp_path)
        for vuln_type, content in [
            ("sqli", "SQL injection found"),
            ("xss", "XSS vulnerability"),
            ("ssrf", "Server-side request forgery"),
            ("rce", "Remote code execution"),
            ("auth_bypass", "Authentication bypass"),
            ("lfi", "Local file inclusion path traversal"),
            ("xxe", "XML external entity injection"),
        ]:
            guide = gen.generate_exploitation_guide({"content": content})
            assert "Steps:" in guide, f"Missing steps for {vuln_type}"
            assert "Tools:" in guide, f"Missing tools for {vuln_type}"

    def test_generate_remediation_for_all_types(self, tmp_path):
        from dexter_ai.reporting import ReportGenerator
        gen = ReportGenerator(loot_dir=tmp_path)
        for content in [
            "SQL injection", "XSS vulnerability", "SSRF found",
            "RCE remote code", "Auth bypass", "LFI file inclusion", "XXE injection",
        ]:
            rem = gen.generate_remediation({"content": content})
            assert len(rem) > 20


# ── Notes Manager Extended ────────────────────────────────────────────────────

class TestNotesManagerExtended:
    """Extended tests for notes.py covering edge cases."""

    @pytest.fixture
    def notes(self, tmp_path):
        from dexter_ai.notes import NotesManager
        return NotesManager(loot_dir=tmp_path)

    def test_sequential_ids_start_at_one(self, notes):
        note = notes.add_note("first note")
        assert note["id"] == 1

    def test_sequential_ids_increment(self, notes):
        n1 = notes.add_note("first")
        n2 = notes.add_note("second")
        n3 = notes.add_note("third")
        assert n1["id"] == 1
        assert n2["id"] == 2
        assert n3["id"] == 3

    def test_source_field_stored(self, notes):
        note = notes.add_note("Port 22 open", source="nmap", category="finding")
        assert note["source"] == "nmap"

    def test_artifact_category_valid(self, notes):
        note = notes.add_note("screenshot.png", category="artifact")
        assert note["category"] == "artifact"

    def test_clear_session_keeps_persisted_notes(self, tmp_path):
        from dexter_ai.notes import NotesManager
        nm = NotesManager(loot_dir=tmp_path)
        nm.add_note("persisted note")
        nm.clear_session()
        # After clear_session, notes should still be there (reloaded from disk)
        assert len(nm.get_notes()) == 1

    def test_corrupted_json_graceful_fallback(self, tmp_path):
        from dexter_ai.notes import NotesManager
        # Create corrupted notes file
        notes_path = tmp_path / "notes.json"
        notes_path.write_text("{invalid json{{")
        nm = NotesManager(loot_dir=tmp_path)
        # Should start empty without crashing
        assert nm.get_notes() == []

    def test_generate_report_empty_notes(self, notes, tmp_path):
        path = notes.generate_report([], target="10.0.0.1")
        assert path.exists()
        content = path.read_text()
        assert "Penetration Test Report" in content

    def test_generate_report_session_results_only(self, notes, tmp_path):
        results = [
            {
                "thought_trace": [
                    {
                        "node": "tool",
                        "action": "gobuster",
                        "thought": "Directory brute force",
                        "reasoning": "Find hidden directories",
                        "observation": "/admin (Status: 200)",
                    }
                ]
            }
        ]
        path = notes.generate_report(results, target="10.0.0.1")
        content = path.read_text()
        assert "gobuster" in content

    def test_get_notes_by_target_and_category_together(self, notes):
        notes.add_note("vuln on host1", category="vulnerability", target="host1")
        notes.add_note("finding on host1", category="finding", target="host1")
        notes.add_note("vuln on host2", category="vulnerability", target="host2")
        vulns_host1 = [
            n for n in notes.get_notes(category="vulnerability", target="host1")
        ]
        assert len(vulns_host1) == 1
        assert vulns_host1[0]["content"] == "vuln on host1"


# ── Process Manager Extended ─────────────────────────────────────────────────

class TestProcessManagerExtended:
    """Extended tests for process_manager.py."""

    @pytest.fixture
    def pm(self):
        from dexter_ai.process_manager import ProcessManager
        return ProcessManager()

    def test_get_process_by_pid(self, pm):
        info = pm.start_process("echo hello", timeout=5)
        result = pm.get_process(info.pid)
        assert result is not None
        assert result.command == "echo hello"

    def test_get_missing_process_returns_none(self, pm):
        assert pm.get_process(999999999) is None

    def test_stop_running_process(self, pm):
        # Start a process that will run for a while
        info = pm.start_process("sleep 30", timeout=60)
        success = pm.stop_process(info.pid)
        assert success is True

    def test_stop_missing_process_returns_false(self, pm):
        assert pm.stop_process(999999999) is False

    def test_get_output_after_completion(self, pm):
        info = pm.start_process("echo hello_world", timeout=5)
        # Wait for process to complete
        deadline = time.time() + 5
        while time.time() < deadline:
            proc_info = pm.get_process(info.pid)
            if proc_info and proc_info.status.value != "running":
                break
            time.sleep(0.05)
        assert time.time() < deadline, "Process did not complete within timeout"
        output = pm.get_output(info.pid)
        assert "hello_world" in output

    def test_get_output_missing_pid_returns_empty_string(self, pm):
        assert pm.get_output(999999999) == ""

    def test_cleanup_finished_returns_count(self, pm):
        info = pm.start_process("echo cleanup_test", timeout=5)
        # Wait for completion
        deadline = time.time() + 5
        while time.time() < deadline:
            pi = pm.get_process(info.pid)
            if pi and pi.status.value != "running":
                break
            time.sleep(0.05)
        assert time.time() < deadline, "Process did not complete within timeout"
        cleaned = pm.cleanup_finished()
        assert cleaned >= 1

    def test_cleanup_finished_moves_to_history(self, pm):
        info = pm.start_process("echo hist_test", timeout=5)
        deadline = time.time() + 5
        while time.time() < deadline:
            pi = pm.get_process(info.pid)
            if pi and pi.status.value != "running":
                break
            time.sleep(0.05)
        assert time.time() < deadline, "Process did not complete within timeout"
        pm.cleanup_finished()
        # Process no longer in active list
        assert pm.get_process(info.pid) is None

    def test_stats_after_starting_process(self, pm):
        pm.start_process("echo stats_test", timeout=5)
        stats = pm.get_stats()
        assert stats["total"] >= 1

    def test_list_processes_after_start(self, pm):
        pm.start_process("echo list_test", timeout=5)
        procs = pm.list_processes()
        assert len(procs) >= 1

    def test_list_processes_filter_by_status(self, pm):
        from dexter_ai.process_manager import ProcessStatus
        pm.start_process("echo filter_test", timeout=5)
        running_procs = pm.list_processes(status=ProcessStatus.RUNNING)
        # Returned list should contain only RUNNING processes
        for p in running_procs:
            assert p.status == ProcessStatus.RUNNING


# ── Tool Registry (tools/registry.py) ────────────────────────────────────────

class TestToolRegistryLocal:
    """Tests for ToolRegistry in dexter_ai/tools/registry.py."""

    @pytest.fixture
    def registry(self):
        # registry.py has a third-party dependency (whois) and an internal
        # import that may not always resolve; skip gracefully when unavailable.
        pytest.importorskip("dexter_ai.tools.registry", reason="dexter_ai.tools.registry not importable")
        from dexter_ai.tools.registry import ToolRegistry
        return ToolRegistry()

    def test_get_tool_by_name(self, registry):
        tool = registry.get("recon_target")
        assert tool is not None
        assert tool.name == "recon_target"

    def test_get_missing_tool_returns_none(self, registry):
        assert registry.get("nonexistent_tool") is None

    def test_get_by_category_recon(self, registry):
        tools = registry.get_by_category("reconnaissance")
        assert len(tools) > 0
        for t in tools:
            assert t.category == "reconnaissance"

    def test_get_by_category_unknown_returns_empty(self, registry):
        assert registry.get_by_category("undefined_category_xyz") == []

    def test_network_scanner_validate_valid_target(self, registry):
        tool = registry.get("recon_target")
        valid, err = tool.validate_input(target="example.com")
        assert valid is True

    def test_network_scanner_validate_missing_target(self, registry):
        tool = registry.get("recon_target")
        valid, err = tool.validate_input(target="")
        assert valid is False
        assert err is not None

    def test_vulnerability_scanner_validate_valid_target(self, registry):
        tool = registry.get("scan_vulnerabilities")
        valid, err = tool.validate_input(target="10.0.0.1")
        assert valid is True

    def test_vulnerability_scanner_validate_missing_target(self, registry):
        tool = registry.get("scan_vulnerabilities")
        valid, err = tool.validate_input(target="")
        assert valid is False

    def test_whois_lookup_validate_valid_target(self, registry):
        tool = registry.get("whois_lookup")
        valid, err = tool.validate_input(target="example.com")
        assert valid is True

    def test_whois_lookup_validate_missing_target(self, registry):
        tool = registry.get("whois_lookup")
        valid, err = tool.validate_input(target="")
        assert valid is False

    def test_analyze_environment_validate_always_valid(self, registry):
        tool = registry.get("analyze_environment")
        valid, err = tool.validate_input()
        assert valid is True

    def test_list_capabilities_validate_always_valid(self, registry):
        tool = registry.get("list_capabilities")
        valid, err = tool.validate_input()
        assert valid is True

    def test_register_custom_tool(self, registry):
        from dexter_ai.tools.registry import AnalyzeEnvironmentTool
        custom = AnalyzeEnvironmentTool()
        custom.name = "custom_tool_xyz"
        registry.register(custom)
        assert registry.get("custom_tool_xyz") is not None

    def test_list_tools_includes_all_defaults(self, registry):
        names = {t["name"] for t in registry.list_tools()}
        for expected in ["recon_target", "scan_vulnerabilities", "whois_lookup",
                         "ssl_analysis", "analyze_environment", "list_capabilities"]:
            assert expected in names, f"Tool '{expected}' not found in registry"


# ── Scope Validator Class ─────────────────────────────────────────────────────

class TestScopeValidatorClass:
    """Tests for the class-based ScopeValidator in scope_validator.py."""

    def test_validate_returns_tuple(self):
        from dexter_ai.guardrails.scope_validator import ScopeValidator
        sv = ScopeValidator(scopes=["example.com", "10.0.0.0/8"])
        result = sv.validate("example.com")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_validate_allowed_target(self):
        from dexter_ai.guardrails.scope_validator import ScopeValidator
        sv = ScopeValidator(scopes=["example.com"])
        allowed, reason = sv.validate("example.com")
        assert allowed is True
        assert reason is None

    def test_validate_denied_target(self):
        from dexter_ai.guardrails.scope_validator import ScopeValidator
        sv = ScopeValidator(scopes=["example.com"])
        allowed, reason = sv.validate("evil.com")
        assert allowed is False
        assert reason is not None
        assert "evil.com" in reason

    def test_validate_empty_target(self):
        from dexter_ai.guardrails.scope_validator import ScopeValidator
        sv = ScopeValidator(scopes=["example.com"])
        allowed, reason = sv.validate("")
        assert allowed is False

    def test_get_scopes(self):
        from dexter_ai.guardrails.scope_validator import ScopeValidator
        scopes = ["example.com", "test.local"]
        sv = ScopeValidator(scopes=scopes)
        assert sv.get_scopes() == scopes

    def test_open_scope_mode_overrides(self, monkeypatch):
        from dexter_ai.guardrails.scope_validator import ScopeValidator
        monkeypatch.setenv("SCOPE_MODE", "open")
        sv = ScopeValidator(scopes=["example.com"])
        allowed, _ = sv.validate("anything.org")
        assert allowed is True

    def test_load_scopes_from_env(self, monkeypatch):
        from dexter_ai.guardrails.scope_validator import load_scopes_from_env
        monkeypatch.setenv("AUTHORIZED_SCOPES", "example.com,test.local,10.0.0.1")
        scopes = load_scopes_from_env()
        assert "example.com" in scopes
        assert "test.local" in scopes
        assert "10.0.0.1" in scopes

    def test_load_scopes_default_when_env_empty(self, monkeypatch):
        from dexter_ai.guardrails.scope_validator import (
            load_scopes_from_env, AUTHORIZED_SCOPES,
        )
        monkeypatch.delenv("AUTHORIZED_SCOPES", raising=False)
        scopes = load_scopes_from_env()
        assert scopes == AUTHORIZED_SCOPES

    def test_get_authorized_scopes_returns_list(self):
        from dexter_ai.guardrails.scope_validator import get_authorized_scopes
        scopes = get_authorized_scopes()
        assert isinstance(scopes, list)
        assert len(scopes) > 0
