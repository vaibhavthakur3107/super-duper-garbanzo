# Web Application Pentesting Methodology

## Scope & Authorization
Always verify written authorization before testing. Never test systems you don't own
or have explicit permission to assess.

## Phase 1 – Reconnaissance (Passive)
- WHOIS / DNS enumeration (A, MX, TXT, NS, CNAME)
- Certificate transparency logs (crt.sh) for subdomain discovery
- Shodan/Censys for exposed services
- Google dorking: site:target.com filetype:pdf

## Phase 2 – Scanning
- Port scan: `nmap -sV -sC -T4 -p- target`
- Service fingerprinting: banner grabbing, HTTP headers
- Web tech detection: Wappalyzer, whatweb

## Phase 3 – Enumeration
- Directory brute-force: gobuster, feroxbuster
- Parameter discovery: Arjun, ffuf
- Subdomain brute-force: dnsx, amass
- Check robots.txt, sitemap.xml, .well-known/

## Phase 4 – Vulnerability Assessment
- Run nuclei templates (critical/high first)
- Check for default credentials
- Test for OWASP Top 10:
  - Injection (SQLi, XSS, SSTI, SSRF)
  - Broken Authentication
  - IDOR / BAC
  - XXE
  - CSRF
  - Security Misconfigurations

## Phase 5 – Exploitation (if authorized)
- Validate findings with minimal impact PoCs
- Document exact steps for reproduction
- Note CVSS scores

## Phase 6 – Reporting
- Executive summary (non-technical)
- Technical findings with evidence
- Risk rating per finding (Critical/High/Medium/Low/Informational)
- Remediation recommendations
- Appendix: raw tool output
