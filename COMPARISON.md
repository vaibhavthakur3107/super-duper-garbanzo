# 🔍 Cyber-Sentry AI vs HexStrike / PentAGI — Honest Comparison

> **Short answer:** No, Cyber-Sentry is not 100% feature-equivalent to HexStrike AI (150-170 tools) or PentAGI.
> It started with 8 tool wrappers. After this expansion it has **67 tool wrappers** across 9 categories.
> This document explains every difference honestly so you know exactly what you have and what to build next.

---

## 📊 Quick Stats Table

| Feature | HexStrike AI v6 | HexStrike CE (Community) | PentAGI | **Cyber-Sentry AI** |
|---|---|---|---|---|
| **Tool count** | 150+ | 170+ | 20+ (sandboxed) | **67** |
| **AI agents** | 12+ | 12+ | 4 (Researcher/Dev/Exec/Orch) | **4** |
| **LLM providers** | Any MCP-compatible | Any MCP-compatible | 9+ (Bedrock, Gemini, DeepSeek…) | **4** (Ollama/OpenAI/Anthropic/OpenRouter) |
| **Architecture** | MCP server + client | MCP server + client | Go microservices + Docker sandbox | **Python monolith + LangGraph** |
| **UI** | None (uses Claude/VSCode/Cursor) | None | React + TypeScript web app | **Streamlit + React (both)** |
| **Database** | None | None | PostgreSQL + pgvector | **SQLite** |
| **Knowledge graph** | None | None | Neo4j + Graphiti | ❌ Not yet |
| **Monitoring** | Real-time dashboard | Real-time dashboard | Grafana + VictoriaMetrics + Jaeger + Loki | ❌ Not yet |
| **Search engines** | None | None | 7 (Google, DDG, Tavily, Sploitus…) | **2** (Tavily + DDG) |
| **Playbooks** | Automated workflows | Automated workflows | Tasks/flows | **7** |
| **Knowledge base** | None | None | Built-in vector KB | **5 methodology files** |
| **Scope guardrails** | None | None | Docker isolation | **7 guardrails** |
| **Tests** | Unknown | Unknown | Yes | **105 passing** |
| **Self-hostable** | Yes | Yes | Yes | **Yes** |
| **License** | Unknown | MIT | MIT | **MIT** |

---

## 🔧 Tool-by-Tool Comparison

### ✅ Tools Cyber-Sentry HAS (67 total)

#### Network Reconnaissance (17)
| Tool | Cyber-Sentry | HexStrike | Notes |
|---|---|---|---|
| nmap | ✅ | ✅ | |
| rustscan | ✅ | ✅ | |
| masscan | ✅ | ✅ | |
| autorecon | ✅ | ✅ | |
| amass | ✅ | ✅ | |
| subfinder | ✅ | ✅ | |
| fierce | ✅ | ✅ | |
| dnsenum | ✅ | ✅ | |
| theHarvester | ✅ | ✅ | |
| enum4linux / enum4linux-ng | ✅ | ✅ | |
| smbmap | ✅ | ✅ | |
| netexec (CrackMapExec) | ✅ | ✅ | |
| nbtscan | ✅ | ✅ | |
| arp-scan | ✅ | ✅ | |
| whois | ✅ | ✅ | |
| dig | ✅ | ✅ | |
| curl | ✅ | (built-in) | |

#### Web Application (22)
| Tool | Cyber-Sentry | HexStrike | Notes |
|---|---|---|---|
| gobuster | ✅ | ✅ | |
| feroxbuster | ✅ | ✅ | |
| ffuf | ✅ | ✅ | |
| dirsearch | ✅ | ✅ | |
| dirb | ❌ | ✅ | Easy to add |
| nikto | ✅ | ✅ | |
| nuclei | ✅ | ✅ | |
| sqlmap | ✅ | ✅ | |
| wpscan | ✅ | ✅ | |
| httpx | ✅ | ✅ | |
| katana | ✅ | ✅ | |
| hakrawler | ✅ | ✅ | |
| gau | ✅ | ✅ | |
| waybackurls | ✅ | ✅ | |
| arjun | ✅ | ✅ | |
| paramspider | ✅ | ✅ | |
| dalfox | ✅ | ✅ | XSS |
| wafw00f | ✅ | ✅ | |
| testssl / sslscan | ✅ | ✅ | |
| whatweb | ✅ | ✅ | |
| wfuzz | ✅ | ✅ | |
| commix | ✅ | ✅ | |
| tplmap | ✅ | ✅ | SSTI |
| jwt-tool | ✅ | ✅ | |
| x8 | ❌ | ✅ | Hidden param discovery |
| jaeles | ❌ | ✅ | Custom vuln signatures |
| nosqlmap | ❌ | ✅ | NoSQL injection |

#### Authentication & Password (6)
| Tool | Cyber-Sentry | HexStrike | Notes |
|---|---|---|---|
| hydra | ✅ | ✅ | |
| john the ripper | ✅ | ✅ | |
| hashcat | ✅ | ✅ | |
| medusa | ✅ | ✅ | |
| evil-winrm | ✅ | ✅ | |
| hash-identifier | ✅ | ✅ | |
| patator | ❌ | ✅ | |
| ophcrack | ❌ | ✅ | |

#### OSINT (8)
| Tool | Cyber-Sentry | HexStrike | Notes |
|---|---|---|---|
| theHarvester | ✅ | ✅ | |
| gau | ✅ | ✅ | |
| waybackurls | ✅ | ✅ | |
| sherlock | ✅ | ✅ | |
| recon-ng | ✅ | ✅ | |
| trufflehog | ✅ | ✅ | |
| shodan | ✅ (needs API key) | ✅ | |
| spiderfoot | ✅ | ✅ | |
| aquatone | ❌ | ✅ | Screenshots |
| subjack | ❌ | ✅ | Subdomain takeover |
| social-analyzer | ❌ | ✅ | |
| maltego | ❌ | ✅ | GUI tool |

#### Forensics & Binary Analysis (9)
| Tool | Cyber-Sentry | HexStrike | Notes |
|---|---|---|---|
| volatility3 | ✅ | ✅ | Memory forensics |
| binwalk | ✅ | ✅ | Firmware |
| foremost | ✅ | ✅ | File carving |
| steghide | ✅ | ✅ | Steganography |
| exiftool | ✅ | ✅ | Metadata |
| gdb | ✅ | ✅ | Debugger |
| radare2 | ✅ | ✅ | RE framework |
| strings | ✅ | ✅ | |
| checksec | ✅ | ✅ | |
| ghidra | ❌ | ✅ | GUI + headless |
| pwntools | ❌ | ✅ | CTF exploit framework |
| angr | ❌ | ✅ | Symbolic execution |
| gdb-peda / gdb-gef | ❌ | ✅ | GDB extensions |
| ropgadget / ropper | ❌ | ✅ | ROP gadget finder |
| stegsolve / zsteg | ❌ | ✅ | Advanced steg |

#### Cloud Security (5)
| Tool | Cyber-Sentry | HexStrike | Notes |
|---|---|---|---|
| trivy | ✅ | ✅ | Container scanning |
| prowler | ✅ | ✅ | AWS/Azure/GCP CIS |
| kube-hunter | ✅ | ✅ | K8s pentest |
| docker-bench-security | ✅ | ✅ | Docker CIS |
| cloud_enum | ✅ | ✅ | Public resource enum |
| scout suite | ❌ | ✅ | Multi-cloud audit |
| pacu | ❌ | ✅ | AWS exploitation |
| falco | ❌ | ✅ | Runtime security |
| checkov / terrascan | ❌ | ✅ | IaC scanning |

---

## ❌ What Cyber-Sentry Does NOT Have (vs HexStrike)

### Missing Tool Categories
| Category | HexStrike Count | Cyber-Sentry | Gap |
|---|---|---|---|
| Browser Agent (headless Chrome) | 10 features | ❌ 0 | Full browser automation for DOM analysis |
| Database direct query tools | 3 (MySQL/PG/SQLite) | ❌ 0 | Direct DB querying without sqlmap |
| Windows-specific tools (BloodHound, Mimikatz) | ~10 | ❌ 0 | AD/Windows exploitation |
| Advanced CTF crypto | ~8 | ❌ 0 | RSATool, frequency analysis, CyberChef |
| BBot | 1 | ❌ 0 | AI-powered recon framework |

### Missing Architectural Features

| Feature | HexStrike | PentAGI | Cyber-Sentry |
|---|---|---|---|
| **Browser Agent** (Selenium + headless Chrome) | ✅ Full DOM analysis, screenshots, JS exec | ❌ | ❌ |
| **Smart caching** (LRU result cache) | ✅ | Redis cache | ❌ |
| **Process management** (live kill/monitor) | ✅ Dashboard | ❌ | ❌ |
| **CVE Intelligence Engine** | ✅ Real-time CVE feed | ❌ | ❌ |
| **Exploit Generator Agent** | ✅ AI-generated PoC | ❌ | ❌ |
| **Knowledge Graph** (Neo4j + Graphiti) | ❌ | ✅ | ❌ |
| **Vector store / RAG** (pgvector) | ❌ | ✅ | ❌ plain keyword KB |
| **Distributed tracing** (Jaeger) | ❌ | ✅ | ❌ |
| **LLM observability** (Langfuse) | ❌ | ✅ | ❌ |
| **Metrics dashboard** (Grafana) | ❌ | ✅ | ❌ |
| **Sploitus exploit search** | ❌ | ✅ | ❌ |
| **Multiple search engines** (Perplexity, etc.) | ❌ | 7 engines | 2 (Tavily + DDG) |
| **GraphQL API** | ❌ | ✅ | ❌ (REST only) |
| **AWS Bedrock / Gemini / DeepSeek / Moonshot** | ❌ | ✅ | ❌ |
| **Sandboxed tool execution** (isolated Docker) | ❌ | ✅ | ❌ (runs directly) |
| **Chain summarisation** (context management) | ❌ | ✅ | ❌ |
| **Profile flags** (--profile web/cloud/binary) | ❌ | ❌ | ❌ |
| **Compact mode** (--compact minimal tools) | Community only | ❌ | ❌ |

---

## ✅ What Cyber-Sentry Has That the Others DON'T

| Feature | Cyber-Sentry | HexStrike | PentAGI |
|---|---|---|---|
| **LangGraph state machine** (transparent reasoning) | ✅ | ❌ | ❌ |
| **Structured thought trace** (every step logged) | ✅ | ❌ | Partial |
| **7 safety guardrails** (scope, prompt injection, legal, output filtering, audit log) | ✅ | ❌ | Docker isolation only |
| **Built-in Streamlit web UI** (no extra client needed) | ✅ | ❌ (needs Claude/VSCode) | ✅ |
| **Interactive CLI REPL** (`cyber-sentry>` shell) | ✅ | ❌ | ❌ |
| **Persistent notes/loot system** (JSON, per-target, per-category) | ✅ | ❌ | Partial |
| **Markdown report generation** (from thought trace + notes) | ✅ | ❌ | ✅ |
| **4 ready-to-run attack playbooks** → now **7** | ✅ | Workflows | Tasks |
| **Knowledge base** (5 methodology files, keyword RAG) | ✅ | ❌ | ✅ (advanced) |
| **105 unit tests** (no LLM or network needed) | ✅ | Unknown | Yes |
| **Single .env config** for everything | ✅ | Partial | ✅ |
| **Fully open architecture** (add any tool with 3 lines of Python) | ✅ | Harder | ❌ (Go) |

---

## 🗺️ Roadmap: How to Reach HexStrike-Level (150+ Tools)

To close the gap from 67 → 150+ tools, here's what to add next (in priority order):

### Priority 1 — High Impact, Easy to Add
```
dirb, x8, jaeles, nosqlmap, patator, subjack, aquatone
sslyze, gau (already have), anew, uro, qsreplace
gdb-peda/gef plugin, ropgadget, ropper
```

### Priority 2 — Medium Effort
```
Browser Agent: selenium + headless Chrome (screenshots, DOM analysis, JS exec)
Smart caching: functools.lru_cache or Redis for repeated scans
Process manager: psutil-based live tool monitoring
BBot: AI-powered recon framework wrapper
```

### Priority 3 — Significant Effort
```
CVE Intelligence: real-time CVE feed integration (NVD API)
Exploit Generator: template-based PoC generation
Neo4j / knowledge graph (optional, massive improvement)
Langfuse LLM observability integration
Additional LLM providers: Gemini, DeepSeek, AWS Bedrock, Moonshot
Profile flags (--profile web / cloud / binary / ctf)
Sandboxed execution (run tools in Docker containers)
```

### Priority 4 — Enterprise Features (from PentAGI)
```
GraphQL API
Grafana + VictoriaMetrics monitoring
ClickHouse analytics
Chain summarisation for context management
Multiple search engines (Perplexity, Sploitus, Searxng)
```

---

## 📌 Summary

| | Status |
|---|---|
| Tools (67/170+) | 🟡 39% of HexStrike CE |
| Core pentest workflow | ✅ Complete |
| Web app testing | ✅ ~90% of HexStrike |
| Network recon | ✅ ~90% of HexStrike |
| Cloud security | ✅ ~60% of HexStrike |
| Binary/Forensics | ✅ ~60% of HexStrike |
| OSINT | ✅ ~65% of HexStrike |
| Auth/Password | ✅ ~75% of HexStrike |
| Browser automation | ❌ 0% |
| Enterprise monitoring | ❌ 0% of PentAGI |
| Knowledge graph | ❌ 0% of PentAGI |

**Bottom line:** Cyber-Sentry has all the essential tools for professional penetration testing, CTF solving, and bug bounty hunting. It covers 7 of 9 tool categories that HexStrike covers. The main gaps are: browser agent automation, advanced Windows/AD tools (BloodHound, Mimikatz), and enterprise observability (Grafana, Langfuse). These can all be added incrementally.
