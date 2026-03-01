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
    allowed_tools = [
        # Original
        'nmap', 'nikto', 'gobuster', 'nuclei', 'sqlmap', 'whois', 'dig',
        'host', 'curl', 'wget',
        # Network
        'rustscan', 'masscan', 'autorecon', 'amass', 'subfinder', 'fierce',
        'dnsenum', 'theHarvester', 'theharvester', 'enum4linux', 'smbmap',
        'netexec', 'nbtscan', 'arp-scan', 'arp_scan', 'crackmapexec',
        # Web
        'feroxbuster', 'ffuf', 'dirsearch', 'httpx', 'katana', 'hakrawler',
        'gau', 'waybackurls', 'wpscan', 'arjun', 'paramspider', 'dalfox',
        'wafw00f', 'testssl.sh', 'testssl', 'sslscan', 'whatweb', 'wfuzz',
        'commix', 'tplmap', 'python3',
        # Auth
        'hydra', 'john', 'hashcat', 'medusa', 'evil-winrm', 'evil_winrm',
        'hash-identifier', 'hash_identifier',
        # OSINT
        'sherlock', 'recon-ng', 'trufflehog', 'shodan', 'spiderfoot',
        # Forensics/Binary
        'vol.py', 'volatility3', 'binwalk', 'foremost', 'steghide',
        'exiftool', 'gdb', 'r2', 'radare2', 'strings', 'checksec',
        # Cloud
        'prowler', 'trivy', 'kube-hunter', 'docker-bench-security',
        'cloud_enum',
        # Shell utils
        'echo',
    ]
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


# ============================================================================
# Network Reconnaissance Tools
# ============================================================================

def rustscan(command: str, target: str) -> str:
    """Ultra-fast port scanner. Finds all open ports, then passes them to nmap."""
    if not command or command == "rustscan":
        command = f"rustscan -a {target} --ulimit 5000 -- -sV -sC"
    return run_command(command, timeout=300)


def masscan(command: str, target: str) -> str:
    """High-speed Internet-scale port scanner with banner grabbing."""
    if not command or command == "masscan":
        command = f"masscan {target} -p1-65535 --rate=1000"
    return run_command(command, timeout=600)


def autorecon(command: str, target: str) -> str:
    """Comprehensive automated multi-threaded network reconnaissance tool."""
    if not command or command == "autorecon":
        command = f"autorecon {target} --only-scans-dir"
    return run_command(command, timeout=1800)


def amass_enum(command: str, target: str) -> str:
    """Advanced subdomain enumeration and OSINT gathering (OWASP Amass)."""
    if not command or command == "amass":
        command = f"amass enum -passive -d {target}"
    return run_command(command, timeout=600)


def subfinder(command: str, target: str) -> str:
    """Fast passive subdomain discovery with multiple sources."""
    if not command or command == "subfinder":
        command = f"subfinder -d {target} -silent"
    return run_command(command, timeout=300)


def fierce(command: str, target: str) -> str:
    """DNS reconnaissance and zone transfer testing."""
    if not command or command == "fierce":
        command = f"fierce --domain {target}"
    return run_command(command, timeout=120)


def dnsenum(command: str, target: str) -> str:
    """DNS information gathering and subdomain brute-forcing."""
    if not command or command == "dnsenum":
        command = f"dnsenum --noreverse {target}"
    return run_command(command, timeout=300)


def theharvester(command: str, target: str) -> str:
    """Email and subdomain harvesting from multiple OSINT sources."""
    if not command or command == "theharvester":
        command = f"theHarvester -d {target} -b all -l 100"
    return run_command(command, timeout=300)


def enum4linux(command: str, target: str) -> str:
    """SMB enumeration: users, groups, shares, password policies."""
    if not command or command == "enum4linux":
        command = f"enum4linux -a {target}"
    return run_command(command, timeout=300)


def smbmap(command: str, target: str) -> str:
    """SMB share enumeration and access assessment."""
    if not command or command == "smbmap":
        command = f"smbmap -H {target}"
    return run_command(command, timeout=120)


def netexec(command: str, target: str) -> str:
    """Network service exploitation and enumeration framework (formerly CrackMapExec)."""
    if not command or command == "netexec":
        command = f"netexec smb {target} --shares"
    return run_command(command, timeout=120)


def nbtscan(command: str, target: str) -> str:
    """NetBIOS name scanning and enumeration."""
    if not command or command == "nbtscan":
        command = f"nbtscan {target}"
    return run_command(command, timeout=60)


def arp_scan(command: str, target: str) -> str:
    """Network host discovery using ARP requests."""
    if not command or command == "arp-scan":
        command = f"arp-scan {target}"
    return run_command(command, timeout=60)


# ============================================================================
# Web Application Security Tools
# ============================================================================

def feroxbuster(command: str, target: str) -> str:
    """Recursive web content discovery with intelligent filtering."""
    if not command or command == "feroxbuster":
        command = f"feroxbuster -u http://{target} -q --no-state"
    return run_command(command, timeout=600)


def ffuf(command: str, target: str) -> str:
    """Fast web fuzzer for directories, parameters, and virtual hosts."""
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not command or command == "ffuf":
        command = f"ffuf -u http://{target}/FUZZ -w {wordlist} -mc 200,301,302,403 -t 40"
    return run_command(command, timeout=600)


def dirsearch(command: str, target: str) -> str:
    """Advanced directory and file discovery with enhanced logging."""
    if not command or command == "dirsearch":
        command = f"dirsearch -u http://{target} -q"
    return run_command(command, timeout=600)


def httpx(command: str, target: str) -> str:
    """Fast HTTP probing, technology detection, and header analysis."""
    if not command or command == "httpx":
        command = f"httpx -u http://{target} -tech-detect -status-code -title -web-server"
    return run_command(command, timeout=120)


def katana(command: str, target: str) -> str:
    """Next-generation web crawler and endpoint discovery with JavaScript support."""
    if not command or command == "katana":
        command = f"katana -u http://{target} -d 3 -silent"
    return run_command(command, timeout=300)


def hakrawler(command: str, target: str) -> str:
    """Fast web endpoint discovery and URL crawling."""
    if not command or command == "hakrawler":
        command = f"echo http://{target} | hakrawler -depth 3"
    return run_command(command, timeout=120)


def gau(command: str, target: str) -> str:
    """Fetch all known URLs from Wayback Machine, Common Crawl, and other sources."""
    if not command or command == "gau":
        command = f"gau {target}"
    return run_command(command, timeout=120)


def waybackurls(command: str, target: str) -> str:
    """Fetch historical URLs from Wayback Machine archive."""
    if not command or command == "waybackurls":
        command = f"echo {target} | waybackurls"
    return run_command(command, timeout=120)


def wpscan(command: str, target: str) -> str:
    """WordPress security scanner: plugins, themes, users, vulnerabilities."""
    if not command or command == "wpscan":
        command = f"wpscan --url http://{target} --no-update -e ap,at,au"
    return run_command(command, timeout=600)


def arjun(command: str, target: str) -> str:
    """HTTP parameter discovery with intelligent fuzzing."""
    if not command or command == "arjun":
        command = f"arjun -u http://{target}"
    return run_command(command, timeout=300)


def paramspider(command: str, target: str) -> str:
    """Parameter mining from web archives for attack surface discovery."""
    if not command or command == "paramspider":
        command = f"paramspider -d {target}"
    return run_command(command, timeout=120)


def dalfox(command: str, target: str) -> str:
    """Advanced XSS vulnerability scanner with DOM analysis."""
    if not command or command == "dalfox":
        command = f"dalfox url http://{target} --no-spinner"
    return run_command(command, timeout=300)


def wafw00f(command: str, target: str) -> str:
    """Web Application Firewall (WAF) detection and fingerprinting."""
    if not command or command == "wafw00f":
        command = f"wafw00f http://{target}"
    return run_command(command, timeout=60)


def testssl(command: str, target: str) -> str:
    """SSL/TLS configuration testing: ciphers, protocols, vulnerabilities."""
    if not command or command == "testssl":
        command = f"testssl.sh --quiet {target}"
    return run_command(command, timeout=300)


def sslscan(command: str, target: str) -> str:
    """SSL/TLS cipher suite enumeration and certificate analysis."""
    if not command or command == "sslscan":
        command = f"sslscan --no-colour {target}"
    return run_command(command, timeout=60)


def whatweb(command: str, target: str) -> str:
    """Web technology identification and fingerprinting."""
    if not command or command == "whatweb":
        command = f"whatweb -a 3 http://{target}"
    return run_command(command, timeout=60)


def wfuzz(command: str, target: str) -> str:
    """Web application fuzzer with advanced payload generation."""
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not command or command == "wfuzz":
        command = f"wfuzz -c -z file,{wordlist} --hc 404 http://{target}/FUZZ"
    return run_command(command, timeout=600)


def commix(command: str, target: str) -> str:
    """Automated command injection exploitation and detection."""
    if not command or command == "commix":
        command = f"commix --url http://{target} --batch"
    return run_command(command, timeout=300)


def tplmap(command: str, target: str) -> str:
    """Server-Side Template Injection (SSTI) detection and exploitation."""
    if not command or command == "tplmap":
        command = f"tplmap -u http://{target}"
    return run_command(command, timeout=300)


def jwt_tool(command: str, target: str) -> str:
    """JSON Web Token (JWT) testing: algorithm confusion, weak secrets."""
    if not command or command == "jwt_tool":
        command = f"python3 -m jwt_tool --help"
    return run_command(command, timeout=30)


# ============================================================================
# Password & Authentication Cracking Tools
# ============================================================================

def hydra(command: str, target: str) -> str:
    """Network login brute-forcer supporting 50+ protocols (SSH, FTP, HTTP, SMB…)."""
    if not command or command == "hydra":
        command = f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt {target} ssh"
    return run_command(command, timeout=600)


def john_crack(command: str, target: str) -> str:
    """John the Ripper — password hash cracking with custom rules."""
    if not command or command == "john":
        command = f"john --show --format=auto {target}"
    return run_command(command, timeout=300)


def hashcat(command: str, target: str) -> str:
    """World's fastest GPU-accelerated password recovery (300+ hash types)."""
    if not command or command == "hashcat":
        command = f"hashcat --help | head -20"
    return run_command(command, timeout=30)


def medusa(command: str, target: str) -> str:
    """Parallel, modular login brute-forcer (SSH, FTP, HTTP, MySQL…)."""
    if not command or command == "medusa":
        command = f"medusa -h {target} -u admin -P /usr/share/wordlists/metasploit/unix_passwords.txt -M ssh"
    return run_command(command, timeout=300)


def evil_winrm(command: str, target: str) -> str:
    """Windows Remote Management (WinRM) shell with PowerShell integration."""
    if not command or command == "evil-winrm":
        command = f"evil-winrm -i {target} --help"
    return run_command(command, timeout=30)


def hash_identify(command: str, target: str) -> str:
    """Identify hash algorithm type from a hash string."""
    if not command or command == "hash-identifier":
        command = f"hash-identifier {target}"
    return run_command(command, timeout=15)


# ============================================================================
# OSINT Tools
# ============================================================================

def sherlock(command: str, target: str) -> str:
    """Username investigation across 400+ social networks."""
    if not command or command == "sherlock":
        command = f"sherlock {target} --timeout 10"
    return run_command(command, timeout=300)


def recon_ng(command: str, target: str) -> str:
    """Web reconnaissance framework with modular architecture."""
    if not command or command == "recon-ng":
        command = f"recon-ng -w default"
    return run_command(command, timeout=60)


def trufflehog(command: str, target: str) -> str:
    """Git repository secret scanning with entropy and pattern analysis."""
    if not command or command == "trufflehog":
        command = f"trufflehog git https://{target} --only-verified"
    return run_command(command, timeout=300)


def shodan_search(command: str, target: str) -> str:
    """Query Shodan API for internet-exposed services on the target."""
    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        return "[!] SHODAN_API_KEY not set. Get a free key at https://account.shodan.io/"
    if not command or command == "shodan":
        command = f"shodan host {target}"
    return run_command(command, timeout=30)


def spiderfoot(command: str, target: str) -> str:
    """OSINT automation framework with 200+ modules."""
    if not command or command == "spiderfoot":
        command = f"spiderfoot -s {target} -t IP_ADDRESS,INTERNET_NAME -q"
    return run_command(command, timeout=600)


# ============================================================================
# Forensics & Binary Analysis Tools
# ============================================================================

def volatility3(command: str, target: str) -> str:
    """Advanced memory forensics framework — analyse memory dumps."""
    if not command or command == "volatility3":
        command = f"python3 vol.py -f {target} windows.pslist.PsList"
    return run_command(command, timeout=300)


def binwalk_scan(command: str, target: str) -> str:
    """Firmware analysis and extraction — find embedded files and code."""
    if not command or command == "binwalk":
        command = f"binwalk -e {target}"
    return run_command(command, timeout=120)


def foremost(command: str, target: str) -> str:
    """File carving and data recovery using file header signatures."""
    if not command or command == "foremost":
        command = f"foremost -i {target} -o /tmp/foremost_output"
    return run_command(command, timeout=300)


def steghide(command: str, target: str) -> str:
    """Steganography detection and data extraction from image files."""
    if not command or command == "steghide":
        command = f"steghide info {target}"
    return run_command(command, timeout=30)


def exiftool(command: str, target: str) -> str:
    """Read and write metadata from files (images, PDFs, documents)."""
    if not command or command == "exiftool":
        command = f"exiftool {target}"
    return run_command(command, timeout=30)


def gdb_debug(command: str, target: str) -> str:
    """GNU Debugger — binary analysis and exploit development."""
    if not command or command == "gdb":
        command = f"gdb --batch --ex 'info file' --ex quit {target}"
    return run_command(command, timeout=30)


def radare2(command: str, target: str) -> str:
    """Advanced reverse engineering framework — disassemble and analyse binaries."""
    if not command or command == "radare2":
        command = f"r2 -A -q -c 'afl' {target}"
    return run_command(command, timeout=120)


def strings_extract(command: str, target: str) -> str:
    """Extract printable strings from binary files."""
    if not command or command == "strings":
        command = f"strings -n 8 {target}"
    return run_command(command, timeout=30)


def checksec(command: str, target: str) -> str:
    """Check binary security properties (ASLR, NX, PIE, RELRO, canary)."""
    if not command or command == "checksec":
        command = f"checksec --file={target}"
    return run_command(command, timeout=15)


# ============================================================================
# Cloud Security Tools
# ============================================================================

def prowler(command: str, target: str) -> str:
    """AWS/Azure/GCP security assessment with CIS benchmark checks."""
    if not command or command == "prowler":
        command = f"prowler aws --profile default -S"
    return run_command(command, timeout=1200)


def trivy_scan(command: str, target: str) -> str:
    """Container and IaC vulnerability scanner (Docker images, filesystems)."""
    if not command or command == "trivy":
        command = f"trivy image {target}"
    return run_command(command, timeout=300)


def kube_hunter(command: str, target: str) -> str:
    """Kubernetes cluster penetration testing (passive + active modes)."""
    if not command or command == "kube-hunter":
        command = f"kube-hunter --remote {target}"
    return run_command(command, timeout=300)


def docker_bench(command: str, target: str) -> str:
    """Docker CIS benchmark security assessment."""
    if not command or command == "docker-bench-security":
        command = f"docker-bench-security"
    return run_command(command, timeout=120)


def cloud_enum(command: str, target: str) -> str:
    """Multi-cloud public resource enumeration (S3 buckets, Azure blobs, GCP)."""
    if not command or command == "cloud_enum":
        command = f"cloud_enum -k {target} -l /tmp/cloud_enum_results.txt"
    return run_command(command, timeout=300)


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
            # ── Original tools ─────────────────────────────────────────────
            "nmap_scan": {
                "function": nmap_scan,
                "description": "Network port scanner and service detection",
                "category": "reconnaissance",
            },
            "nikto_scan": {
                "function": nikto_scan,
                "description": "Web server vulnerability scanner",
                "category": "vulnerability",
            },
            "gobuster_scan": {
                "function": gobuster_scan,
                "description": "Directory and file enumeration",
                "category": "enumeration",
            },
            "nuclei_scan": {
                "function": nuclei_scan,
                "description": "Fast vulnerability scanner with 4000+ templates",
                "category": "vulnerability",
            },
            "sqlmap_scan": {
                "function": sqlmap_scan,
                "description": "Automatic SQL injection detection and exploitation",
                "category": "vulnerability",
            },
            "whois_lookup": {
                "function": whois_lookup,
                "description": "WHOIS domain registration lookup",
                "category": "reconnaissance",
            },
            "dig_lookup": {
                "function": dig_lookup,
                "description": "DNS record enumeration",
                "category": "reconnaissance",
            },
            "curl_scan": {
                "function": curl_scan,
                "description": "HTTP header and response analysis",
                "category": "reconnaissance",
            },
            # ── Network Reconnaissance ─────────────────────────────────────
            "rustscan": {
                "function": rustscan,
                "description": "Ultra-fast port scanner (wraps nmap)",
                "category": "reconnaissance",
            },
            "masscan": {
                "function": masscan,
                "description": "High-speed Internet-scale port scanning",
                "category": "reconnaissance",
            },
            "autorecon": {
                "function": autorecon,
                "description": "Automated multi-threaded network reconnaissance",
                "category": "reconnaissance",
            },
            "amass_enum": {
                "function": amass_enum,
                "description": "Subdomain enumeration and OSINT (OWASP Amass)",
                "category": "reconnaissance",
            },
            "subfinder": {
                "function": subfinder,
                "description": "Passive subdomain discovery with multiple sources",
                "category": "reconnaissance",
            },
            "fierce": {
                "function": fierce,
                "description": "DNS reconnaissance and zone transfer testing",
                "category": "reconnaissance",
            },
            "dnsenum": {
                "function": dnsenum,
                "description": "DNS info gathering and subdomain brute-forcing",
                "category": "reconnaissance",
            },
            "theharvester": {
                "function": theharvester,
                "description": "Email and subdomain harvesting from OSINT sources",
                "category": "osint",
            },
            "enum4linux": {
                "function": enum4linux,
                "description": "SMB enumeration: users, groups, shares, policies",
                "category": "enumeration",
            },
            "smbmap": {
                "function": smbmap,
                "description": "SMB share enumeration and access assessment",
                "category": "enumeration",
            },
            "netexec": {
                "function": netexec,
                "description": "Network service exploitation framework (ex-CrackMapExec)",
                "category": "exploitation",
            },
            "nbtscan": {
                "function": nbtscan,
                "description": "NetBIOS name scanning",
                "category": "reconnaissance",
            },
            "arp_scan": {
                "function": arp_scan,
                "description": "Network host discovery via ARP",
                "category": "reconnaissance",
            },
            # ── Web Application Security ───────────────────────────────────
            "feroxbuster": {
                "function": feroxbuster,
                "description": "Recursive web content discovery",
                "category": "enumeration",
            },
            "ffuf": {
                "function": ffuf,
                "description": "Fast web fuzzer for dirs, params, vhosts",
                "category": "enumeration",
            },
            "dirsearch": {
                "function": dirsearch,
                "description": "Advanced directory and file discovery",
                "category": "enumeration",
            },
            "httpx": {
                "function": httpx,
                "description": "Fast HTTP probing and technology detection",
                "category": "reconnaissance",
            },
            "katana": {
                "function": katana,
                "description": "Web crawler with JavaScript support",
                "category": "enumeration",
            },
            "hakrawler": {
                "function": hakrawler,
                "description": "Fast web endpoint discovery",
                "category": "enumeration",
            },
            "gau": {
                "function": gau,
                "description": "Fetch all known URLs from archives",
                "category": "osint",
            },
            "waybackurls": {
                "function": waybackurls,
                "description": "Historical URLs from Wayback Machine",
                "category": "osint",
            },
            "wpscan": {
                "function": wpscan,
                "description": "WordPress vulnerability scanner",
                "category": "vulnerability",
            },
            "arjun": {
                "function": arjun,
                "description": "HTTP parameter discovery",
                "category": "enumeration",
            },
            "paramspider": {
                "function": paramspider,
                "description": "Parameter mining from web archives",
                "category": "enumeration",
            },
            "dalfox": {
                "function": dalfox,
                "description": "Advanced XSS vulnerability scanner",
                "category": "vulnerability",
            },
            "wafw00f": {
                "function": wafw00f,
                "description": "WAF detection and fingerprinting",
                "category": "reconnaissance",
            },
            "testssl": {
                "function": testssl,
                "description": "SSL/TLS configuration testing",
                "category": "vulnerability",
            },
            "sslscan": {
                "function": sslscan,
                "description": "SSL/TLS cipher suite enumeration",
                "category": "vulnerability",
            },
            "whatweb": {
                "function": whatweb,
                "description": "Web technology identification",
                "category": "reconnaissance",
            },
            "wfuzz": {
                "function": wfuzz,
                "description": "Web application fuzzer",
                "category": "enumeration",
            },
            "commix": {
                "function": commix,
                "description": "Command injection exploitation",
                "category": "vulnerability",
            },
            "tplmap": {
                "function": tplmap,
                "description": "Server-Side Template Injection (SSTI) testing",
                "category": "vulnerability",
            },
            "jwt_tool": {
                "function": jwt_tool,
                "description": "JWT testing (algorithm confusion, weak secrets)",
                "category": "vulnerability",
            },
            # ── Authentication & Password Tools ────────────────────────────
            "hydra": {
                "function": hydra,
                "description": "Network login brute-forcer (50+ protocols)",
                "category": "authentication",
            },
            "john_crack": {
                "function": john_crack,
                "description": "Password hash cracking (John the Ripper)",
                "category": "authentication",
            },
            "hashcat": {
                "function": hashcat,
                "description": "GPU-accelerated password recovery (300+ hash types)",
                "category": "authentication",
            },
            "medusa": {
                "function": medusa,
                "description": "Parallel modular login brute-forcer",
                "category": "authentication",
            },
            "evil_winrm": {
                "function": evil_winrm,
                "description": "Windows Remote Management shell",
                "category": "exploitation",
            },
            "hash_identify": {
                "function": hash_identify,
                "description": "Hash algorithm type identification",
                "category": "authentication",
            },
            # ── OSINT Tools ────────────────────────────────────────────────
            "sherlock": {
                "function": sherlock,
                "description": "Username investigation across 400+ social networks",
                "category": "osint",
            },
            "recon_ng": {
                "function": recon_ng,
                "description": "Web reconnaissance framework",
                "category": "osint",
            },
            "trufflehog": {
                "function": trufflehog,
                "description": "Git repository secret scanning",
                "category": "osint",
            },
            "shodan_search": {
                "function": shodan_search,
                "description": "Shodan internet exposure lookup (needs SHODAN_API_KEY)",
                "category": "osint",
            },
            "spiderfoot": {
                "function": spiderfoot,
                "description": "OSINT automation with 200+ modules",
                "category": "osint",
            },
            # ── Forensics & Binary Analysis ────────────────────────────────
            "volatility3": {
                "function": volatility3,
                "description": "Memory forensics framework",
                "category": "forensics",
            },
            "binwalk_scan": {
                "function": binwalk_scan,
                "description": "Firmware analysis and extraction",
                "category": "forensics",
            },
            "foremost": {
                "function": foremost,
                "description": "File carving and data recovery",
                "category": "forensics",
            },
            "steghide": {
                "function": steghide,
                "description": "Steganography detection and extraction",
                "category": "forensics",
            },
            "exiftool": {
                "function": exiftool,
                "description": "File metadata reader and writer",
                "category": "forensics",
            },
            "gdb_debug": {
                "function": gdb_debug,
                "description": "GNU Debugger — binary analysis",
                "category": "binary",
            },
            "radare2": {
                "function": radare2,
                "description": "Advanced reverse engineering framework",
                "category": "binary",
            },
            "strings_extract": {
                "function": strings_extract,
                "description": "Extract printable strings from binaries",
                "category": "binary",
            },
            "checksec": {
                "function": checksec,
                "description": "Binary security property checker",
                "category": "binary",
            },
            # ── Cloud Security ─────────────────────────────────────────────
            "prowler": {
                "function": prowler,
                "description": "AWS/Azure/GCP CIS benchmark security assessment",
                "category": "cloud",
            },
            "trivy_scan": {
                "function": trivy_scan,
                "description": "Container and IaC vulnerability scanner",
                "category": "cloud",
            },
            "kube_hunter": {
                "function": kube_hunter,
                "description": "Kubernetes penetration testing",
                "category": "cloud",
            },
            "docker_bench": {
                "function": docker_bench,
                "description": "Docker CIS benchmark security assessment",
                "category": "cloud",
            },
            "cloud_enum": {
                "function": cloud_enum,
                "description": "Multi-cloud public resource enumeration",
                "category": "cloud",
            },
            # ── Web Search ─────────────────────────────────────────────────
            "web_search": {
                "function": web_search,
                "description": "AI web search (Tavily or DuckDuckGo fallback)",
                "category": "reconnaissance",
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
