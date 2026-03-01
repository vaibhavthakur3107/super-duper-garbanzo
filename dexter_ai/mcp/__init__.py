"""
Dexter AI Pentest – MCP (Model Context Protocol) Client
Manages connections to external MCP tool servers.

Inspired by PentestAgent's MCP integration:
  https://github.com/GH05TCREW/pentestagent

MCP servers expose tools via a standardised JSON protocol, allowing
Dexter AI Pentest to call external tools (nmap MCP, Metasploit MCP, Burp Suite
extensions, custom tool servers, etc.) transparently alongside built-in tools.
"""

from __future__ import annotations

import json
import os
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Default config file locations
_DEFAULT_CONFIG_PATHS = [
    Path("mcp_servers.json"),
    Path.home() / ".config" / "dexter-ai" / "mcp_servers.json",
]


@dataclass
class MCPServerConfig:
    """Configuration for a single MCP server."""
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "args": self.args,
            "env": self.env,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "MCPServerConfig":
        return cls(
            name=name,
            command=data.get("command", ""),
            args=data.get("args", []),
            env=data.get("env", {}),
            description=data.get("description", ""),
        )


class MCPClient:
    """
    Manages MCP server configurations and provides a tool-call interface.

    MCP servers are external processes that speak the Model Context Protocol
    (a JSON-RPC variant).  Dexter AI Pentest uses a lightweight subprocess-based
    client that:
      1. Loads server configs from ``mcp_servers.json``
      2. Verifies that server commands exist on ``PATH``
      3. Exposes ``call_tool()`` for calling tools on a running server

    This is intentionally lightweight – it provides the configuration and
    discovery layer; the actual JSON-RPC framing is left to the MCP SDK if
    it is installed (``mcp`` package), or gracefully degrades to a subprocess
    call otherwise.
    """

    def __init__(self, config_path: Optional[Path] = None):
        self._config_path: Path = self._resolve_config(config_path)
        self._servers: dict[str, MCPServerConfig] = {}
        self._load()

    # ── Config management ────────────────────────────────────────────────────

    @staticmethod
    def _resolve_config(config_path: Optional[Path]) -> Path:
        if config_path:
            return Path(config_path)
        for p in _DEFAULT_CONFIG_PATHS:
            if p.exists():
                return p
        return Path("mcp_servers.json")

    def _load(self):
        """Load server configs from disk."""
        if not self._config_path.exists():
            return
        try:
            raw = json.loads(self._config_path.read_text())
            servers = raw.get("mcpServers", {})
            self._servers = {
                name: MCPServerConfig.from_dict(name, cfg)
                for name, cfg in servers.items()
            }
            logger.info("Loaded %d MCP server(s) from %s", len(self._servers), self._config_path)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load MCP config %s: %s", self._config_path, exc)

    def _save(self):
        """Persist current server configs to disk."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "mcpServers": {
                name: cfg.to_dict()
                for name, cfg in self._servers.items()
            }
        }
        self._config_path.write_text(json.dumps(data, indent=2))

    # ── Public API ───────────────────────────────────────────────────────────

    def list_servers(self) -> list[dict]:
        """Return all configured MCP servers."""
        result = []
        for name, cfg in self._servers.items():
            available = shutil.which(cfg.command) is not None
            result.append({
                "name": name,
                "command": cfg.command,
                "args": cfg.args,
                "description": cfg.description,
                "available": available,
            })
        return result

    def add_server(
        self,
        name: str,
        command: str,
        args: Optional[list[str]] = None,
        env: Optional[dict[str, str]] = None,
        description: str = "",
    ) -> MCPServerConfig:
        """Add (or update) an MCP server configuration."""
        cfg = MCPServerConfig(
            name=name,
            command=command,
            args=args or [],
            env=env or {},
            description=description,
        )
        self._servers[name] = cfg
        self._save()
        return cfg

    def remove_server(self, name: str) -> bool:
        """Remove an MCP server by name. Returns True if it existed."""
        if name in self._servers:
            del self._servers[name]
            self._save()
            return True
        return False

    def get_server(self, name: str) -> Optional[MCPServerConfig]:
        """Get a server config by name."""
        return self._servers.get(name)

    def test_server(self, name: str) -> tuple[bool, str]:
        """
        Check whether the MCP server command exists and is executable.
        Returns (success, message).
        """
        cfg = self._servers.get(name)
        if not cfg:
            return False, f"Server '{name}' not found in config"
        if not shutil.which(cfg.command):
            return False, f"Command '{cfg.command}' not found on PATH"
        return True, f"Server '{name}' ({cfg.command}) is available"

    def call_tool(self, server_name: str, tool_name: str, arguments: dict) -> dict:
        """
        Call a tool on an MCP server.

        Uses the ``mcp`` Python SDK if installed; falls back to a basic
        subprocess invocation otherwise.

        Returns a dict with keys:
            ``success`` (bool), ``result`` (any), ``error`` (str | None)
        """
        cfg = self._servers.get(server_name)
        if not cfg:
            return {"success": False, "result": None, "error": f"Unknown MCP server: {server_name}"}

        # Try MCP SDK first
        try:
            return self._call_via_sdk(cfg, tool_name, arguments)
        except ImportError:
            pass

        # Fallback: pass arguments as JSON via stdin to the subprocess
        return self._call_via_subprocess(cfg, tool_name, arguments)

    def _call_via_sdk(self, cfg: MCPServerConfig, tool_name: str, arguments: dict) -> dict:
        """Use the official ``mcp`` SDK (if installed)."""
        # This import will raise ImportError if mcp is not installed,
        # which triggers the subprocess fallback.
        from mcp import ClientSession, StdioServerParameters  # type: ignore[import]
        from mcp.client.stdio import stdio_client  # type: ignore[import]
        import asyncio

        async def _run():
            params = StdioServerParameters(
                command=cfg.command,
                args=cfg.args,
                env={**os.environ, **cfg.env},
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool_name, arguments)
                    return result

        result = asyncio.run(_run())
        return {"success": True, "result": str(result), "error": None}

    def _call_via_subprocess(self, cfg: MCPServerConfig, tool_name: str, arguments: dict) -> dict:
        """
        Minimal fallback: launch the server, write a JSON-RPC call to stdin,
        read the response from stdout.
        """
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        })
        env = {**os.environ, **cfg.env}
        try:
            proc = subprocess.run(
                [cfg.command, *cfg.args],
                input=payload,
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
            )
            if proc.returncode != 0:
                return {"success": False, "result": None, "error": f"non-zero exit: {proc.returncode}"}
            response = json.loads(proc.stdout)
            return {"success": True, "result": response.get("result"), "error": None}
        except subprocess.TimeoutExpired:
            return {"success": False, "result": None, "error": "MCP server timed out"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "result": None, "error": str(exc)}
