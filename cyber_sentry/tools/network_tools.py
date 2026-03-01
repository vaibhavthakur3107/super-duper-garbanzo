"""
Network Security Tools
Safe wrappers for pentesting tools: nmap, nikto, gobuster, nuclei, etc.
Inspired by pentest-mcp-server and pentagi
"""

import subprocess
import re
import json
import os
from typing import Optional, Tuple
from pathlib import Path


def sanitize_command(command: str) -> Tuple[bool, str]:
    """
    Sanitize shell commands to prevent injection.
    Returns (is_valid, error_message)
    """
    # Block dangerous patterns
    dangerous_patterns = [
        r';\s*rm\s+-rf',  # Delete commands
        r';\s*fork\(\)',  # Fork bombs
        r'&\s*&\s*rm',    # Chain delete
        r'\|\s*sh',       # Pipe to shell
        r'>\s*/dev/sd',   # Direct disk write
        r'sudo\s+',       # Privilege escalation
        r'chmod\s+777',   # Permission changes
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"Dangerous command pattern detected: {pattern}"
    
    # Ensure command starts with allowed tools
    allowed_tools = ['nmap', 'nikto', 'gobuster', 'nuclei', 'sqlmap', 'whois', 'dig', 'host', 'curl', 'wget']
    first_word = command.strip().split()[0] if command.strip() else ""
    
    if first_word and not any(first_word.startswith(tool) for tool in allowed_tools):
        # Allow if it's a common utility
        if first_word not in ['cat', 'ls', 'grep', 'head', 'tail', 'awk', 'sed']:
            return False, f"Tool '{first_word}' is not in the allowed list"
    
    return True, ""


def run_command(command: str, timeout: int = 300) -> str:
    """
    Safely execute a shell command and return output.
    """
    is_valid, error = sanitize_command(command)
    if not is_valid:
        raise ValueError(f"Command validation failed: {error}")
    
    # Set PATH to include common tool locations
    env = os.environ.copy()
    env['PATH'] = '/usr/local/bin:/usr/bin:/bin:' + env.get('PATH', '')
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            stderr=subprocess.STDOUT
        )
        
        output = result.stdout if result.stdout else result.stderr
        
        # Truncate very long outputs
        if len(output) > 100000:
            output = output[:100000] + "\n... [output truncated]"
        
        return output
        
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Error executing command: {str(e)}"


# ============================================================================
# Tool Functions
# ============================================================================

def nmap_scan(command: str, target: str) -> str:
    """
    Execute nmap scan.
    Command should be like: nmap -sV -sC -oA scan_results target
    """
    # If only target provided, use default scan
    if not command or command == "nmap":
        command = f"nmap -sV -sC -T4 -oA nmap_scan {target}"
    
    return run_command(command, timeout=600)


def nikto_scan(command: str, target: str) -> str:
    """
    Execute nikto scan for web vulnerabilities.
    """
    if not command or command == "nikto":
        # Add -Format htm to get HTML output, or txt for text
        command = f"nikto -h http://{target} -o nikto_scan.txt"
    
    return run_command(command, timeout=900)


def gobuster_scan(command: str, target: str) -> str:
    """
    Execute gobuster for directory enumeration.
    """
    if not command or command == "gobuster":
        # Common wordlist location
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        
        command = f"gobuster dir -u http://{target} -w {wordlist} -o gobuster_results.txt"
    
    return run_command(command, timeout=1200)


def nuclei_scan(command: str, target: str) -> str:
    """
    Execute nuclei for vulnerability scanning.
    """
    if not command or command == "nuclei":
        command = f"nuclei -u http://{target} -severity critical,high,medium -o nuclei_results.txt"
    
    return run_command(command, timeout=1200)


def sqlmap_scan(command: str, target: str) -> str:
    """
    Execute sqlmap for SQL injection testing.
    CAUTION: Only for authorized testing!
    """
    if not command or command == "sqlmap":
        command = f"sqlmap -u http://{target} --batch --risk=1 --level=1"
    
    return run_command(command, timeout=1800)


def whois_lookup(command: str, target: str) -> str:
    """
    Perform WHOIS lookup on target domain.
    """
    # Strip protocol if present
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    
    if not command or command == "whois":
        command = f"whois {target}"
    
    return run_command(command, timeout=30)


def dig_lookup(command: str, target: str) -> str:
    """
    Perform DNS lookup using dig.
    """
    # Strip protocol if present
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    
    if not command or command == "dig":
        command = f"dig {target} ANY +short"
    
    return run_command(command, timeout=30)


def curl_scan(command: str, target: str) -> str:
    """
    Perform curl request for information gathering.
    """
    if not command or command == "curl":
        command = f"curl -I -L http://{target}"
    
    return run_command(command, timeout=60)


def extract_ports(nmap_output: str) -> list:
    """Extract open ports from nmap output"""
    ports = []
    
    # Match patterns like "80/tcp   open  http"
    pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)'
    matches = re.findall(pattern, nmap_output)
    
    for port, protocol, service in matches:
        ports.append({
            "port": int(port),
            "protocol": protocol,
            "service": service
        })
    
    return ports


def extract_urls(gobuster_output: str) -> list:
    """Extract discovered URLs from gobuster output"""
    urls = []
    
    # Match patterns like "/admin (Status: 200)"
    pattern = r'(/\S+)\s+\(Status:\s+(\d+)\)'
    matches = re.findall(pattern, gobuster_output)
    
    for path, status in matches:
        if status in ['200', '301', '302', '403']:
            urls.append({"path": path, "status": status})
    
    return urls


def extract_cves(nuclei_output: str) -> list:
    """Extract CVE information from nuclei output"""
    cves = []
    
    # Match patterns like "[CVE-2024-XXXX]"
    pattern = r'\[(CVE-\d+-\d+)\]'
    matches = re.findall(pattern, nuclei_output)
    
    cves = list(set(matches))
    return cves


def web_search(query: str, target: str = "") -> str:
    """
    Perform a web search using Tavily API (like PentestAgent).
    Falls back to a curl-based DuckDuckGo instant-answer query when
    TAVILY_API_KEY is not set.

    Args:
        query: Search query string
        target: Optional target context (prepended to query if provided)
    """
    if target and target not in query:
        query = f"{query} {target}"

    api_key = os.environ.get("TAVILY_API_KEY", "")

    if api_key:
        try:
            import httpx  # already in requirements.txt
            response = httpx.post(
                "https://api.tavily.com/search",
                headers={"Content-Type": "application/json"},
                json={
                    "api_key": api_key,
                    "query": query,
                    "search_depth": "basic",
                    "include_answer": True,
                    "max_results": 5,
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            answer = data.get("answer", "")
            results = data.get("results", [])
            lines = []
            if answer:
                lines.append(f"Answer: {answer}\n")
            for r in results:
                lines.append(f"[{r.get('title', '')}] {r.get('url', '')}")
                if r.get("content"):
                    lines.append(f"  {r['content'][:200]}")
            return "\n".join(lines) if lines else "No results found."
        except Exception as e:  # noqa: BLE001
            return f"Tavily search error: {e}"

    # Fallback: DuckDuckGo instant-answer API (no key required)
    safe_query = query.replace(" ", "+")
    command = (
        f'curl -s "https://api.duckduckgo.com/?q={safe_query}&format=json&no_html=1&skip_disambig=1"'
    )
    output = run_command(command, timeout=15)
    try:
        import json as _json
        data = _json.loads(output)
        abstract = data.get("AbstractText", "")
        related = [r.get("Text", "") for r in data.get("RelatedTopics", [])[:3]]
        parts = []
        if abstract:
            parts.append(f"Summary: {abstract}")
        if related:
            parts.append("Related:\n" + "\n".join(f"  - {t}" for t in related if t))
        return "\n".join(parts) if parts else f"No instant answer for: {query}"
    except Exception:  # noqa: BLE001
        return output or f"No results for: {query}"


class ToolRegistry:
    """Registry of all available security tools"""
    
    def __init__(self):
        self.tools = {
            "nmap_scan": {
                "function": nmap_scan,
                "description": "Network port scanner",
                "category": "reconnaissance"
            },
            "nikto_scan": {
                "function": nikto_scan,
                "description": "Web vulnerability scanner",
                "category": "vulnerability"
            },
            "gobuster_scan": {
                "function": gobuster_scan,
                "description": "Directory/file enumeration",
                "category": "enumeration"
            },
            "nuclei_scan": {
                "function": nuclei_scan,
                "description": "Vulnerability scanner with templates",
                "category": "vulnerability"
            },
            "sqlmap_scan": {
                "function": sqlmap_scan,
                "description": "SQL injection scanner",
                "category": "vulnerability"
            },
            "whois_lookup": {
                "function": whois_lookup,
                "description": "WHOIS domain lookup",
                "category": "reconnaissance"
            },
            "dig_lookup": {
                "function": dig_lookup,
                "description": "DNS lookup tool",
                "category": "reconnaissance"
            },
            "web_search": {
                "function": web_search,
                "description": "Web search (Tavily or DuckDuckGo fallback)",
                "category": "reconnaissance"
            },
        }
    
    def list_tools(self) -> list:
        """List all available tools"""
        return [
            {
                "name": name,
                "description": info["description"],
                "category": info["category"]
            }
            for name, info in self.tools.items()
        ]
    
    def get_tool(self, name: str):
        """Get tool by name"""
        tool_info = self.tools.get(name)
        return tool_info["function"] if tool_info else None


# Create global registry instance
tool_registry = ToolRegistry()
