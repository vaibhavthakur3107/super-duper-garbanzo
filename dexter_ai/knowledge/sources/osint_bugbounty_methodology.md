# OSINT & Bug Bounty Reconnaissance Methodology

## Phase 1 – Passive Subdomain Enumeration
- `amass enum -passive -d target.com` — passive OSINT from 50+ sources
- `subfinder -d target.com -silent` — fast passive discovery
- `theHarvester -d target.com -b all` — email, subdomain, IP harvesting
- Certificate transparency: `curl -s https://crt.sh/?q=%25.target.com&output=json`
- ASN lookup: `amass intel -asn <ASN>` — find all IPs owned by org

## Phase 2 – URL & Endpoint Collection
- `gau target.com` — all URLs from Wayback, CommonCrawl, OTX, URLScan
- `waybackurls target.com` — Wayback Machine archive
- `katana -u https://target.com -d 4` — live spidering with JS support
- `echo target.com | hakrawler` — fast endpoint discovery
- Deduplicate: `sort -u urls.txt | uro > clean_urls.txt`

## Phase 3 – Technology Detection
- `httpx -l hosts.txt -tech-detect -status-code -title -cdn`
- `whatweb https://target.com` — CMS, framework, server detection
- `wafw00f https://target.com` — WAF detection before fuzzing

## Phase 4 – Parameter Discovery
- `arjun -u https://target.com/endpoint` — parameter fuzzing
- `paramspider -d target.com` — mine params from archives
- `x8 -u https://target.com -w wordlist.txt` — hidden parameter discovery

## Phase 5 – Common Bug Classes to Test
### SSRF (Server-Side Request Forgery)
- Test all URL parameters with: `http://169.254.169.254/latest/meta-data/`
- Blind SSRF: use collaborator/interactsh

### Open Redirect
- Test `redirect=`, `url=`, `next=`, `return=` parameters
- Payload: `?redirect=https://evil.com`

### XSS (Cross-Site Scripting)
- `dalfox url https://target.com?param=FUZZ`
- Test reflected parameters, stored inputs, DOM sinks

### IDOR (Insecure Direct Object Reference)
- Increment/fuzz numeric IDs in API endpoints
- Try UUIDs from one account on another account's objects

### SQLi
- `sqlmap -u https://target.com/search?q=1 --dbs`

## Phase 6 – Secret Scanning
- `trufflehog git https://github.com/target/repo --only-verified`
- Search JS files: `grep -r "api_key\|secret\|password\|token" *.js`
- Google dork: `site:github.com "target.com" "api_key"`

## Phase 7 – Rate Limit & Authentication Testing
- Check `/forgot-password`, `/reset-password` for rate limiting
- Test JWT: `jwt_tool <token> -T` — check alg:none, RS256→HS256
- 2FA bypass: reuse OTP, race condition on OTP validation
