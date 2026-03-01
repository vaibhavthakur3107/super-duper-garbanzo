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
        # API Security
        'graphql-cop', 'newman', 'restler', 'swagger-cli',
        'oauth-tester', 'cors-scanner',
        'rate-limit-tester', 'wsdl-analyzer', 'grpc_cli',
        # Wireless Security
        'aircrack-ng', 'wifite', 'kismet', 'bettercap', 'reaver',
        'wash', 'mdk4', 'hostapd-wpe',
        # Mobile Security
        'apktool', 'jadx', 'frida', 'objection', 'mobsf',
        'drozer', 'ios-deploy', 'needle',
        # Additional Network
        'responder', 'mitm6', 'tcpdump', 'tshark', 'nc', 'netcat',
        'snmpwalk', 'onesixtyone',
        # Additional Web
        'xsstrike', 'nosqlmap', 'ssrf-detect', 'lfi-detect',
        'xxe-detect', 'crlfuzz', 'open-redirect-scanner',
        'host-header-check', 'clickjack-test', 'subjack',
        # Exploitation
        'msfconsole', 'searchsploit', 'msfvenom', 'impacket',
        'bloodhound-python', 'mimikatz',
        # CTF
        'ROPgadget', 'one_gadget', 'z3', 'stegsolve', 'zsteg',
        # Additional Cloud/Container
        'scout', 'pacu', 'cloudsploit', 'terraform-compliance',
        'checkov', 'falco',
        # Additional OSINT
        'maltego', 'censys', 'hunter', 'dnsdumpster',
        'wayback-discover', 'linkedin-scraper', 'github-dorking',
        # Infrastructure/Misc
        'ansible-lint', 'lynis', 'chkrootkit', 'rkhunter',
        'clamscan', 'yara', 'osqueryi', 'velociraptor',
        # Additional Reconnaissance
        'dnsrecon', 'whatportis',
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


# ============================================================================
# API Security Testing Tools
# ============================================================================

def graphql_introspection(command: str, target: str) -> str:
    """GraphQL schema introspection and analysis."""
    if not command or command == "graphql-cop":
        command = f"graphql-cop -t http://{target}/graphql"
    return run_command(command, timeout=120)


def postman_collection_runner(command: str, target: str) -> str:
    """API endpoint testing from Postman collections."""
    if not command or command == "newman":
        command = f"newman run {target} --reporters cli"
    return run_command(command, timeout=300)


def rest_api_fuzzer(command: str, target: str) -> str:
    """REST API parameter and endpoint fuzzing."""
    if not command or command == "restler":
        command = f"restler fuzz --grammar_file {target} --time_budget 1"
    return run_command(command, timeout=600)


def swagger_scanner(command: str, target: str) -> str:
    """OpenAPI/Swagger specification vulnerability scanning."""
    if not command or command == "swagger-cli":
        command = f"swagger-cli validate {target}"
    return run_command(command, timeout=120)


def oauth_tester(command: str, target: str) -> str:
    """OAuth 2.0 flow and token security testing."""
    if not command or command == "oauth-tester":
        command = f"oauth-tester --url http://{target} --scan-all"
    return run_command(command, timeout=120)


def cors_scanner(command: str, target: str) -> str:
    """Cross-Origin Resource Sharing misconfiguration testing."""
    if not command or command == "cors-scanner":
        command = f"cors-scanner -u http://{target}"
    return run_command(command, timeout=60)


def graphql_cop(command: str, target: str) -> str:
    """GraphQL security auditing tool."""
    if not command or command == "graphql-cop":
        command = f"graphql-cop -t http://{target}/graphql --no-colour"
    return run_command(command, timeout=120)


def api_rate_limit_tester(command: str, target: str) -> str:
    """API rate limiting and throttling analysis."""
    if not command or command == "rate-limit-tester":
        command = f"rate-limit-tester -u http://{target} -n 100"
    return run_command(command, timeout=120)


def soap_scanner(command: str, target: str) -> str:
    """SOAP/XML web service security testing."""
    if not command or command == "wsdl-analyzer":
        command = f"wsdl-analyzer --url http://{target}?wsdl --scan"
    return run_command(command, timeout=120)


def grpc_scanner(command: str, target: str) -> str:
    """gRPC service enumeration and testing."""
    if not command or command == "grpc_cli":
        command = f"grpc_cli ls {target} --l"
    return run_command(command, timeout=60)


# ============================================================================
# Wireless Security Tools
# ============================================================================

def aircrack_ng(command: str, target: str) -> str:
    """WiFi network analysis and security testing."""
    if not command or command == "aircrack-ng":
        command = f"aircrack-ng --help"
    return run_command(command, timeout=30)


def wifite(command: str, target: str) -> str:
    """Automated wireless attack tool."""
    if not command or command == "wifite":
        command = f"wifite --kill --dict /usr/share/wordlists/rockyou.txt -i {target}"
    return run_command(command, timeout=600)


def kismet(command: str, target: str) -> str:
    """Wireless network detector and sniffer."""
    if not command or command == "kismet":
        command = f"kismet -c {target} --no-ncurses"
    return run_command(command, timeout=300)


def bettercap(command: str, target: str) -> str:
    """Network attack and monitoring framework."""
    if not command or command == "bettercap":
        command = f"bettercap -iface {target} -eval 'net.probe on; sleep 5; net.show; quit'"
    return run_command(command, timeout=120)


def reaver(command: str, target: str) -> str:
    """WPS PIN brute-force attack tool."""
    if not command or command == "reaver":
        command = f"reaver -i {target} -b 00:00:00:00:00:00 -vv"
    return run_command(command, timeout=600)


def wash_scan(command: str, target: str) -> str:
    """WPS-enabled network scanner."""
    if not command or command == "wash":
        command = f"wash -i {target}"
    return run_command(command, timeout=60)


def mdk4(command: str, target: str) -> str:
    """WiFi denial-of-service testing tool."""
    if not command or command == "mdk4":
        command = f"mdk4 {target} b -c 1"
    return run_command(command, timeout=60)


def hostapd_wpe(command: str, target: str) -> str:
    """Rogue access point for credential capture."""
    if not command or command == "hostapd-wpe":
        command = f"hostapd-wpe {target}"
    return run_command(command, timeout=300)


# ============================================================================
# Mobile Security Tools
# ============================================================================

def apktool(command: str, target: str) -> str:
    """Android APK reverse engineering."""
    if not command or command == "apktool":
        command = f"apktool d {target} -o /tmp/apktool_output"
    return run_command(command, timeout=120)


def jadx(command: str, target: str) -> str:
    """Android DEX to Java decompiler."""
    if not command or command == "jadx":
        command = f"jadx -d /tmp/jadx_output {target}"
    return run_command(command, timeout=120)


def frida(command: str, target: str) -> str:
    """Dynamic instrumentation toolkit."""
    if not command or command == "frida":
        command = f"frida --list-devices"
    return run_command(command, timeout=30)


def objection(command: str, target: str) -> str:
    """Runtime mobile exploration."""
    if not command or command == "objection":
        command = f"objection -g {target} explore"
    return run_command(command, timeout=120)


def mobsf(command: str, target: str) -> str:
    """Mobile Security Framework automated analysis."""
    if not command or command == "mobsf":
        command = f"mobsf --scan {target}"
    return run_command(command, timeout=600)


def drozer(command: str, target: str) -> str:
    """Android security assessment framework."""
    if not command or command == "drozer":
        command = f"drozer console connect --server {target}"
    return run_command(command, timeout=120)


def ios_deploy(command: str, target: str) -> str:
    """iOS application deployment and testing."""
    if not command or command == "ios-deploy":
        command = f"ios-deploy --bundle {target}"
    return run_command(command, timeout=120)


def needle(command: str, target: str) -> str:
    """iOS security testing framework."""
    if not command or command == "needle":
        command = f"needle -t {target}"
    return run_command(command, timeout=300)


# ============================================================================
# Additional Network Tools
# ============================================================================

def responder(command: str, target: str) -> str:
    """LLMNR/NBT-NS/MDNS poisoner."""
    if not command or command == "responder":
        command = f"responder -I {target} -A"
    return run_command(command, timeout=300)


def mitm6(command: str, target: str) -> str:
    """IPv6 DNS takeover via mitm."""
    if not command or command == "mitm6":
        command = f"mitm6 -d {target}"
    return run_command(command, timeout=300)


def bettercap_net(command: str, target: str) -> str:
    """Network monitoring and MITM."""
    if not command or command == "bettercap":
        command = f"bettercap -T {target} -eval 'net.sniff on; sleep 10; quit'"
    return run_command(command, timeout=120)


def tcpdump(command: str, target: str) -> str:
    """Network packet capture and analysis."""
    if not command or command == "tcpdump":
        command = f"tcpdump -i any -c 100 host {target} -nn"
    return run_command(command, timeout=60)


def wireshark_cli(command: str, target: str) -> str:
    """TShark packet analysis."""
    if not command or command == "tshark":
        command = f"tshark -i any -c 100 -f 'host {target}'"
    return run_command(command, timeout=60)


def netcat_scan(command: str, target: str) -> str:
    """Netcat port scanning and banner grabbing."""
    if not command or command == "nc":
        command = f"nc -zv {target} 1-1024 2>&1"
    return run_command(command, timeout=120)


def snmpwalk(command: str, target: str) -> str:
    """SNMP enumeration and information gathering."""
    if not command or command == "snmpwalk":
        command = f"snmpwalk -v2c -c public {target}"
    return run_command(command, timeout=120)


def onesixtyone(command: str, target: str) -> str:
    """Fast SNMP community string scanner."""
    if not command or command == "onesixtyone":
        command = f"onesixtyone {target} public private"
    return run_command(command, timeout=60)


# ============================================================================
# Additional Web Application Tools
# ============================================================================

def xsstrike(command: str, target: str) -> str:
    """Advanced XSS detection suite."""
    if not command or command == "xsstrike":
        command = f"xsstrike -u http://{target} --crawl"
    return run_command(command, timeout=300)


def nosql_injection(command: str, target: str) -> str:
    """NoSQL injection detection."""
    if not command or command == "nosqlmap":
        command = f"nosqlmap -u http://{target} --attack 1"
    return run_command(command, timeout=300)


def ssrf_scanner(command: str, target: str) -> str:
    """SSRF vulnerability detection."""
    if not command or command == "ssrf-detect":
        command = f"ssrf-detect -u http://{target}"
    return run_command(command, timeout=120)


def lfi_scanner(command: str, target: str) -> str:
    """Local File Inclusion testing."""
    if not command or command == "lfi-detect":
        command = f"lfi-detect -u http://{target} --depth 5"
    return run_command(command, timeout=120)


def xxe_scanner(command: str, target: str) -> str:
    """XML External Entity injection testing."""
    if not command or command == "xxe-detect":
        command = f"xxe-detect -u http://{target}"
    return run_command(command, timeout=120)


def crlf_scanner(command: str, target: str) -> str:
    """CRLF injection detection."""
    if not command or command == "crlfuzz":
        command = f"crlfuzz -u http://{target}"
    return run_command(command, timeout=120)


def open_redirect_scanner(command: str, target: str) -> str:
    """Open redirect vulnerability testing."""
    if not command or command == "open-redirect-scanner":
        command = f"open-redirect-scanner -u http://{target}"
    return run_command(command, timeout=120)


def host_header_injection(command: str, target: str) -> str:
    """Host header injection testing."""
    if not command or command == "host-header-check":
        command = f"host-header-check -u http://{target}"
    return run_command(command, timeout=60)


def clickjacking_tester(command: str, target: str) -> str:
    """Clickjacking vulnerability testing."""
    if not command or command == "clickjack-test":
        command = f"clickjack-test -u http://{target}"
    return run_command(command, timeout=60)


def subdomain_takeover(command: str, target: str) -> str:
    """Subdomain takeover detection."""
    if not command or command == "subjack":
        command = f"subjack -d {target} -ssl -v"
    return run_command(command, timeout=300)


# ============================================================================
# Exploitation Tools
# ============================================================================

def metasploit(command: str, target: str) -> str:
    """Metasploit framework console."""
    if not command or command == "msfconsole":
        command = f"msfconsole -q -x 'search {target}; exit'"
    return run_command(command, timeout=120)


def searchsploit(command: str, target: str) -> str:
    """Exploit-DB offline search."""
    if not command or command == "searchsploit":
        command = f"searchsploit {target}"
    return run_command(command, timeout=30)


def msfvenom(command: str, target: str) -> str:
    """Payload generation with Metasploit."""
    if not command or command == "msfvenom":
        command = f"msfvenom --list payloads | grep {target}"
    return run_command(command, timeout=60)


def responder_exploit(command: str, target: str) -> str:
    """LLMNR/NBT-NS poisoning attacks."""
    if not command or command == "responder":
        command = f"responder -I {target} -wrf"
    return run_command(command, timeout=300)


def impacket_tools(command: str, target: str) -> str:
    """Network protocol exploitation suite."""
    if not command or command == "impacket":
        command = f"impacket-smbclient {target}"
    return run_command(command, timeout=120)


def crackmapexec(command: str, target: str) -> str:
    """Network service exploitation (legacy)."""
    if not command or command == "crackmapexec":
        command = f"crackmapexec smb {target} --shares"
    return run_command(command, timeout=120)


def bloodhound(command: str, target: str) -> str:
    """Active Directory attack path analysis."""
    if not command or command == "bloodhound-python":
        command = f"bloodhound-python -d {target} -c All"
    return run_command(command, timeout=300)


def mimikatz(command: str, target: str) -> str:
    """Windows credential extraction (for reference)."""
    if not command or command == "mimikatz":
        command = f"mimikatz 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'"
    return run_command(command, timeout=60)


# ============================================================================
# CTF Tools
# ============================================================================

def pwntools(command: str, target: str) -> str:
    """CTF exploitation framework."""
    if not command or command == "python3":
        command = f"python3 -c 'from pwn import *; print(cyclic(100))'"
    return run_command(command, timeout=30)


def ropgadget(command: str, target: str) -> str:
    """ROP gadget finder for binary exploitation."""
    if not command or command == "ROPgadget":
        command = f"ROPgadget --binary {target}"
    return run_command(command, timeout=120)


def one_gadget(command: str, target: str) -> str:
    """Find one-shot gadgets in libc."""
    if not command or command == "one_gadget":
        command = f"one_gadget {target}"
    return run_command(command, timeout=60)


def z3_solver(command: str, target: str) -> str:
    """Z3 SMT solver for crypto/reversing challenges."""
    if not command or command == "z3":
        command = f"python3 -c 'from z3 import *; print(get_version_string())'"
    return run_command(command, timeout=30)


def stegsolve(command: str, target: str) -> str:
    """Steganography analysis tool."""
    if not command or command == "stegsolve":
        command = f"stegsolve -f {target}"
    return run_command(command, timeout=60)


def zsteg(command: str, target: str) -> str:
    """PNG/BMP steganography detection."""
    if not command or command == "zsteg":
        command = f"zsteg {target}"
    return run_command(command, timeout=60)


def john_wordlist(command: str, target: str) -> str:
    """Custom wordlist generation with John."""
    if not command or command == "john":
        command = f"john --wordlist=/usr/share/wordlists/rockyou.txt --rules --stdout | head -1000"
    return run_command(command, timeout=60)


def cyberchef(command: str, target: str) -> str:
    """Data encoding/decoding Swiss Army knife."""
    if not command or command == "python3":
        command = f"python3 -c \"import base64; print(base64.b64decode('{target}').decode('utf-8', errors='replace'))\""
    return run_command(command, timeout=15)


# ============================================================================
# Additional Cloud & Container Security Tools
# ============================================================================

def scout_suite(command: str, target: str) -> str:
    """Multi-cloud security auditing."""
    if not command or command == "scout":
        command = f"scout aws --report-dir /tmp/scout_report"
    return run_command(command, timeout=600)


def pacu(command: str, target: str) -> str:
    """AWS exploitation framework."""
    if not command or command == "pacu":
        command = f"pacu --help"
    return run_command(command, timeout=30)


def cloudsploit(command: str, target: str) -> str:
    """Cloud security configuration scanner."""
    if not command or command == "cloudsploit":
        command = f"cloudsploit scan --config {target}"
    return run_command(command, timeout=600)


def terraform_compliance(command: str, target: str) -> str:
    """Terraform security compliance checking."""
    if not command or command == "terraform-compliance":
        command = f"terraform-compliance -f {target} -p plan.out"
    return run_command(command, timeout=120)


def checkov(command: str, target: str) -> str:
    """IaC static analysis for security."""
    if not command or command == "checkov":
        command = f"checkov -d {target} --quiet"
    return run_command(command, timeout=300)


def falco(command: str, target: str) -> str:
    """Container runtime security monitoring."""
    if not command or command == "falco":
        command = f"falco --list"
    return run_command(command, timeout=30)


# ============================================================================
# Additional OSINT Tools
# ============================================================================

def maltego(command: str, target: str) -> str:
    """OSINT and link analysis."""
    if not command or command == "maltego":
        command = f"maltego --help"
    return run_command(command, timeout=30)


def censys_search(command: str, target: str) -> str:
    """Censys internet device search."""
    if not command or command == "censys":
        command = f"censys search {target}"
    return run_command(command, timeout=60)


def hunter_io(command: str, target: str) -> str:
    """Email address finder."""
    if not command or command == "hunter":
        command = f"hunter --domain {target}"
    return run_command(command, timeout=60)


def haveibeenpwned(command: str, target: str) -> str:
    """Breach database checker."""
    if not command or command == "python3":
        command = f"curl -s 'https://haveibeenpwned.com/api/v3/breachedaccount/{target}' -H 'hibp-api-key: test'"
    return run_command(command, timeout=30)


def dnsdumpster(command: str, target: str) -> str:
    """DNS reconnaissance."""
    if not command or command == "dnsdumpster":
        command = f"dnsdumpster -d {target}"
    return run_command(command, timeout=120)


def wayback_discover(command: str, target: str) -> str:
    """Wayback Machine domain discovery."""
    if not command or command == "wayback-discover":
        command = f"wayback-discover -d {target}"
    return run_command(command, timeout=120)


def linkedin_scraper(command: str, target: str) -> str:
    """Professional network OSINT."""
    if not command or command == "linkedin-scraper":
        command = f"linkedin-scraper --company {target}"
    return run_command(command, timeout=120)


def github_dorking(command: str, target: str) -> str:
    """GitHub code/secret searching."""
    if not command or command == "github-dorking":
        command = f"github-dorking -o {target} -t /tmp/gh_dork_results.txt"
    return run_command(command, timeout=120)


# ============================================================================
# Infrastructure & Miscellaneous Security Tools
# ============================================================================

def ansible_lint(command: str, target: str) -> str:
    """Infrastructure playbook security."""
    if not command or command == "ansible-lint":
        command = f"ansible-lint {target}"
    return run_command(command, timeout=120)


def lynis(command: str, target: str) -> str:
    """Unix system security auditing."""
    if not command or command == "lynis":
        command = f"lynis audit system --quick --no-colors"
    return run_command(command, timeout=300)


def chkrootkit(command: str, target: str) -> str:
    """Rootkit detection."""
    if not command or command == "chkrootkit":
        command = f"chkrootkit -q"
    return run_command(command, timeout=120)


def rkhunter(command: str, target: str) -> str:
    """Rootkit and backdoor detection."""
    if not command or command == "rkhunter":
        command = f"rkhunter --check --skip-keypress --report-warnings-only"
    return run_command(command, timeout=300)


def clamav_scan(command: str, target: str) -> str:
    """Malware/virus scanning."""
    if not command or command == "clamscan":
        command = f"clamscan -r {target} --no-summary"
    return run_command(command, timeout=600)


def yara_scan(command: str, target: str) -> str:
    """YARA rule-based malware pattern matching."""
    if not command or command == "yara":
        command = f"yara -r /tmp/rules.yar {target}"
    return run_command(command, timeout=120)


def osquery(command: str, target: str) -> str:
    """OS-level analytics and monitoring."""
    if not command or command == "osqueryi":
        command = f"osqueryi --json 'SELECT * FROM listening_ports'"
    return run_command(command, timeout=30)


def velociraptor(command: str, target: str) -> str:
    """Endpoint visibility and collection."""
    if not command or command == "velociraptor":
        command = f"velociraptor query 'SELECT * FROM info()'"
    return run_command(command, timeout=60)


def dnsrecon(command: str, target: str) -> str:
    """DNS enumeration, zone transfer testing, and record brute-forcing."""
    if not command or command == "dnsrecon":
        command = f"dnsrecon -d {target} -t std"
    return run_command(command, timeout=120)


def whatportis(command: str, target: str) -> str:
    """Port and service name lookup database."""
    if not command or command == "whatportis":
        command = f"whatportis {target} --like"
    return run_command(command, timeout=15)


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
            # ── API Security Testing ──────────────────────────────────────
            "api_rate_limit_tester": {
                "function": api_rate_limit_tester,
                "description": "API rate limiting and throttling analysis",
                "category": "api_security",
            },
            "cors_scanner": {
                "function": cors_scanner,
                "description": "CORS misconfiguration testing",
                "category": "api_security",
            },
            "graphql_cop": {
                "function": graphql_cop,
                "description": "GraphQL security auditing tool",
                "category": "api_security",
            },
            "graphql_introspection": {
                "function": graphql_introspection,
                "description": "GraphQL schema introspection and analysis",
                "category": "api_security",
            },
            "grpc_scanner": {
                "function": grpc_scanner,
                "description": "gRPC service enumeration and testing",
                "category": "api_security",
            },
            "oauth_tester": {
                "function": oauth_tester,
                "description": "OAuth 2.0 flow and token security testing",
                "category": "api_security",
            },
            "postman_collection_runner": {
                "function": postman_collection_runner,
                "description": "API endpoint testing from Postman collections",
                "category": "api_security",
            },
            "rest_api_fuzzer": {
                "function": rest_api_fuzzer,
                "description": "REST API parameter and endpoint fuzzing",
                "category": "api_security",
            },
            "soap_scanner": {
                "function": soap_scanner,
                "description": "SOAP/XML web service security testing",
                "category": "api_security",
            },
            "swagger_scanner": {
                "function": swagger_scanner,
                "description": "OpenAPI/Swagger specification vulnerability scanning",
                "category": "api_security",
            },
            # ── Wireless Security ─────────────────────────────────────────
            "aircrack_ng": {
                "function": aircrack_ng,
                "description": "WiFi network analysis and security testing",
                "category": "wireless",
            },
            "bettercap": {
                "function": bettercap,
                "description": "Network attack and monitoring framework",
                "category": "wireless",
            },
            "hostapd_wpe": {
                "function": hostapd_wpe,
                "description": "Rogue access point for credential capture",
                "category": "wireless",
            },
            "kismet": {
                "function": kismet,
                "description": "Wireless network detector and sniffer",
                "category": "wireless",
            },
            "mdk4": {
                "function": mdk4,
                "description": "WiFi denial-of-service testing tool",
                "category": "wireless",
            },
            "reaver": {
                "function": reaver,
                "description": "WPS PIN brute-force attack tool",
                "category": "wireless",
            },
            "wash_scan": {
                "function": wash_scan,
                "description": "WPS-enabled network scanner",
                "category": "wireless",
            },
            "wifite": {
                "function": wifite,
                "description": "Automated wireless attack tool",
                "category": "wireless",
            },
            # ── Mobile Security ────────────────────────────────────────────
            "apktool": {
                "function": apktool,
                "description": "Android APK reverse engineering",
                "category": "mobile",
            },
            "drozer": {
                "function": drozer,
                "description": "Android security assessment framework",
                "category": "mobile",
            },
            "frida": {
                "function": frida,
                "description": "Dynamic instrumentation toolkit",
                "category": "mobile",
            },
            "ios_deploy": {
                "function": ios_deploy,
                "description": "iOS application deployment and testing",
                "category": "mobile",
            },
            "jadx": {
                "function": jadx,
                "description": "Android DEX to Java decompiler",
                "category": "mobile",
            },
            "mobsf": {
                "function": mobsf,
                "description": "Mobile Security Framework automated analysis",
                "category": "mobile",
            },
            "needle": {
                "function": needle,
                "description": "iOS security testing framework",
                "category": "mobile",
            },
            "objection": {
                "function": objection,
                "description": "Runtime mobile exploration",
                "category": "mobile",
            },
            # ── Additional Network Tools ───────────────────────────────────
            "bettercap_net": {
                "function": bettercap_net,
                "description": "Network monitoring and MITM",
                "category": "reconnaissance",
            },
            "mitm6": {
                "function": mitm6,
                "description": "IPv6 DNS takeover via mitm",
                "category": "exploitation",
            },
            "netcat_scan": {
                "function": netcat_scan,
                "description": "Netcat port scanning and banner grabbing",
                "category": "reconnaissance",
            },
            "onesixtyone": {
                "function": onesixtyone,
                "description": "Fast SNMP community string scanner",
                "category": "reconnaissance",
            },
            "responder": {
                "function": responder,
                "description": "LLMNR/NBT-NS/MDNS poisoner",
                "category": "exploitation",
            },
            "snmpwalk": {
                "function": snmpwalk,
                "description": "SNMP enumeration and information gathering",
                "category": "enumeration",
            },
            "tcpdump": {
                "function": tcpdump,
                "description": "Network packet capture and analysis",
                "category": "reconnaissance",
            },
            "wireshark_cli": {
                "function": wireshark_cli,
                "description": "TShark packet analysis",
                "category": "reconnaissance",
            },
            # ── Additional Web Application Tools ──────────────────────────
            "clickjacking_tester": {
                "function": clickjacking_tester,
                "description": "Clickjacking vulnerability testing",
                "category": "vulnerability",
            },
            "crlf_scanner": {
                "function": crlf_scanner,
                "description": "CRLF injection detection",
                "category": "vulnerability",
            },
            "host_header_injection": {
                "function": host_header_injection,
                "description": "Host header injection testing",
                "category": "vulnerability",
            },
            "lfi_scanner": {
                "function": lfi_scanner,
                "description": "Local File Inclusion testing",
                "category": "vulnerability",
            },
            "nosql_injection": {
                "function": nosql_injection,
                "description": "NoSQL injection detection",
                "category": "vulnerability",
            },
            "open_redirect_scanner": {
                "function": open_redirect_scanner,
                "description": "Open redirect vulnerability testing",
                "category": "vulnerability",
            },
            "ssrf_scanner": {
                "function": ssrf_scanner,
                "description": "SSRF vulnerability detection",
                "category": "vulnerability",
            },
            "subdomain_takeover": {
                "function": subdomain_takeover,
                "description": "Subdomain takeover detection",
                "category": "vulnerability",
            },
            "xsstrike": {
                "function": xsstrike,
                "description": "Advanced XSS detection suite",
                "category": "vulnerability",
            },
            "xxe_scanner": {
                "function": xxe_scanner,
                "description": "XML External Entity injection testing",
                "category": "vulnerability",
            },
            # ── Exploitation Tools ────────────────────────────────────────
            "bloodhound": {
                "function": bloodhound,
                "description": "Active Directory attack path analysis",
                "category": "exploitation",
            },
            "crackmapexec": {
                "function": crackmapexec,
                "description": "Network service exploitation (legacy)",
                "category": "exploitation",
            },
            "impacket_tools": {
                "function": impacket_tools,
                "description": "Network protocol exploitation suite",
                "category": "exploitation",
            },
            "metasploit": {
                "function": metasploit,
                "description": "Metasploit framework console",
                "category": "exploitation",
            },
            "mimikatz": {
                "function": mimikatz,
                "description": "Windows credential extraction (for reference)",
                "category": "exploitation",
            },
            "msfvenom": {
                "function": msfvenom,
                "description": "Payload generation with Metasploit",
                "category": "exploitation",
            },
            "responder_exploit": {
                "function": responder_exploit,
                "description": "LLMNR/NBT-NS poisoning attacks",
                "category": "exploitation",
            },
            "searchsploit": {
                "function": searchsploit,
                "description": "Exploit-DB offline search",
                "category": "exploitation",
            },
            # ── CTF Tools ─────────────────────────────────────────────────
            "cyberchef": {
                "function": cyberchef,
                "description": "Data encoding/decoding Swiss Army knife",
                "category": "ctf",
            },
            "john_wordlist": {
                "function": john_wordlist,
                "description": "Custom wordlist generation with John",
                "category": "ctf",
            },
            "one_gadget": {
                "function": one_gadget,
                "description": "Find one-shot gadgets in libc",
                "category": "ctf",
            },
            "pwntools": {
                "function": pwntools,
                "description": "CTF exploitation framework",
                "category": "ctf",
            },
            "ropgadget": {
                "function": ropgadget,
                "description": "ROP gadget finder for binary exploitation",
                "category": "ctf",
            },
            "stegsolve": {
                "function": stegsolve,
                "description": "Steganography analysis tool",
                "category": "ctf",
            },
            "z3_solver": {
                "function": z3_solver,
                "description": "Z3 SMT solver for crypto/reversing challenges",
                "category": "ctf",
            },
            "zsteg": {
                "function": zsteg,
                "description": "PNG/BMP steganography detection",
                "category": "ctf",
            },
            # ── Additional Cloud & Container Security ─────────────────────
            "checkov": {
                "function": checkov,
                "description": "IaC static analysis for security",
                "category": "cloud",
            },
            "cloudsploit": {
                "function": cloudsploit,
                "description": "Cloud security configuration scanner",
                "category": "cloud",
            },
            "falco": {
                "function": falco,
                "description": "Container runtime security monitoring",
                "category": "cloud",
            },
            "pacu": {
                "function": pacu,
                "description": "AWS exploitation framework",
                "category": "cloud",
            },
            "scout_suite": {
                "function": scout_suite,
                "description": "Multi-cloud security auditing",
                "category": "cloud",
            },
            "terraform_compliance": {
                "function": terraform_compliance,
                "description": "Terraform security compliance checking",
                "category": "cloud",
            },
            # ── Additional OSINT Tools ────────────────────────────────────
            "censys_search": {
                "function": censys_search,
                "description": "Censys internet device search",
                "category": "osint",
            },
            "dnsdumpster": {
                "function": dnsdumpster,
                "description": "DNS reconnaissance",
                "category": "osint",
            },
            "github_dorking": {
                "function": github_dorking,
                "description": "GitHub code/secret searching",
                "category": "osint",
            },
            "haveibeenpwned": {
                "function": haveibeenpwned,
                "description": "Breach database checker",
                "category": "osint",
            },
            "hunter_io": {
                "function": hunter_io,
                "description": "Email address finder",
                "category": "osint",
            },
            "linkedin_scraper": {
                "function": linkedin_scraper,
                "description": "Professional network OSINT",
                "category": "osint",
            },
            "maltego": {
                "function": maltego,
                "description": "OSINT and link analysis",
                "category": "osint",
            },
            "wayback_discover": {
                "function": wayback_discover,
                "description": "Wayback Machine domain discovery",
                "category": "osint",
            },
            # ── Infrastructure & Miscellaneous ────────────────────────────
            "ansible_lint": {
                "function": ansible_lint,
                "description": "Infrastructure playbook security",
                "category": "infrastructure",
            },
            "chkrootkit": {
                "function": chkrootkit,
                "description": "Rootkit detection",
                "category": "infrastructure",
            },
            "clamav_scan": {
                "function": clamav_scan,
                "description": "Malware/virus scanning",
                "category": "infrastructure",
            },
            "lynis": {
                "function": lynis,
                "description": "Unix system security auditing",
                "category": "infrastructure",
            },
            "osquery": {
                "function": osquery,
                "description": "OS-level analytics and monitoring",
                "category": "infrastructure",
            },
            "rkhunter": {
                "function": rkhunter,
                "description": "Rootkit and backdoor detection",
                "category": "infrastructure",
            },
            "velociraptor": {
                "function": velociraptor,
                "description": "Endpoint visibility and collection",
                "category": "infrastructure",
            },
            "yara_scan": {
                "function": yara_scan,
                "description": "YARA rule-based malware pattern matching",
                "category": "infrastructure",
            },
            # ── Additional Reconnaissance ─────────────────────────────────
            "dnsrecon": {
                "function": dnsrecon,
                "description": "DNS enumeration, zone transfer testing, and record brute-forcing",
                "category": "reconnaissance",
            },
            "whatportis": {
                "function": whatportis,
                "description": "Port and service name lookup database",
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
