<div align="center">

<pre style="background: transparent; border: none;">
██╗  ██╗██╗██████╗  █████╗ ██╗     
██║ ██╔╝██║██╔══██╗██╔══██╗██║     
█████╔╝ ██║██████╔╝███████║██║     
██╔═██╗ ██║██╔══██╗██╔══██║██║     
██║  ██╗██║██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
</pre>

<h3>Attack Surface Intelligence Terminal</h3>

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-00f0ff?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Typer-CLI-00ff41?style=flat-square" alt="Typer CLI">
  <img src="https://img.shields.io/badge/Rich-Terminal-ff9f1c?style=flat-square" alt="Rich Terminal">
  <img src="https://img.shields.io/badge/ClickHouse-Analytics-bd00ff?style=flat-square&logo=clickhouse&logoColor=white" alt="ClickHouse">
  <img src="https://img.shields.io/badge/Redis-Streams-ff0044?style=flat-square&logo=redis&logoColor=white" alt="Redis">
</p>

<p><em>Reconnaissance, automated. Attack surface, illuminated.</em></p>

</div>

---

## 🎯 What is KIRAL?

**KIRAL** is a production-grade, asynchronous Attack Surface Management (ASM) pipeline that transforms raw reconnaissance into structured intelligence. Built for security teams, bug bounty hunters, and infrastructure engineers who need to **see everything** an attacker sees — and see it fast.

Unlike static scripts that dump output to files, KIRAL orchestrates a **6-stage reconnaissance pipeline**, normalizes findings into canonical events, deduplicates them in real-time, and streams everything into **ClickHouse** for lightning-fast analytics. All wrapped in a gorgeous, cyberpunk-themed terminal interface.

<div align="center">

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 1        STAGE 2        STAGE 3        STAGE 4        STAGE 5        │
│  Subdomains  →  DNS Resolve  →  Port Scan   →  URL Discover →  HTTP Probe  │
│  subfinder      dnsx           rustscan       gau + katana     httpx         │
│       │              │              │              │              │          │
│       └──────────────┴──────────────┴──────────────┴──────────────┘          │
│                                          │                                  │
│                                          ▼                                  │
│  STAGE 6 ────────────────────►  Redis Stream  ──►  Consumer  ──► ClickHouse │
│  Vulnerability Detection        asm:events:v1      (ingestor)   (analytics)  │
│  nuclei                                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

</div>

---

## ✨ Features

| Capability | Description |
|-----------|-------------|
| 🔍 **6-Stage Pipeline** | Subdomain enumeration → DNS resolution → port scanning → URL discovery → HTTP probing → vulnerability detection |
| ⚡ **Async & Streamed** | Every tool runs asynchronously with real-time stdout streaming — no waiting for temp files |
| 🧠 **Smart Deduplication** | Redis-backed SHA256 deduplication with 7-day TTL prevents noise on re-scans |
| 📊 **ClickHouse Analytics** | Columnar storage with monthly partitioning — query millions of rows in milliseconds |
| 🎨 **Gorgeous Terminal UI** | Cyberpunk-themed dashboard with neon cyan, matrix green, and plasma purple live HUD |
| 🛡️ **Vulnerability Tracking** | Nuclei integration with severity-colored tables (Critical → Info) |
| 🔧 **10 CLI Commands** | `scan`, `status`, `init`, `query`, `export`, `vulns`, `dashboard`, `debug`, `purge` |
| 🐳 **Dockerized Consumer** | Resilient stream consumer with auto-retry, crash recovery, and batch ingestion |
| 🚨 **Safety Limits** | Hard caps at 500K events per scan, tool timeouts, and graceful shutdowns |

---

## 🚀 Quick Start

### 1. Install

```bash
git clone https://github.com/yourusername/kiral.git
cd kiral
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

### 2. Configure

Copy the example environment file and edit:

```bash
cp .env.example .env
```

```env
ASM_REDIS_HOST=192.168.1.21
ASM_REDIS_PASSWORD=changeme
ASM_CH_URL=http://192.168.1.21:8123/
ASM_CH_USER=asm_ingestor
ASM_CH_PASSWORD=changeme
```

### 3. Initialize the Database

```bash
kiral init
```

### 4. Start the Consumer

```bash
# Docker (recommended)
docker-compose up -d consumer

# Or native
python -m src.run_consumer
```

### 5. Scan Your First Target

```bash
kiral scan example.com
```

Watch the live HUD as KIRAL discovers subdomains, resolves IPs, scans ports, crawls URLs, probes services, and hunts vulnerabilities — all in one fluid sequence.

---

## 🖥️ The KIRAL Terminal

### Live Scan Dashboard

The `kiral scan` command launches a real-time terminal HUD with 6 progress bars, each representing a pipeline stage. As findings stream in, counters update live:

```
┌─ KIRAL Attack Surface Intelligence ───────────────────────────────────────┐
│  [████████████████████░░░░░░░░░░] Stage 1  —  847 subdomains found       │
│  [████████████████░░░░░░░░░░░░░░] Stage 2  —  1,203 DNS records          │
│  [████████████░░░░░░░░░░░░░░░░░░] Stage 3  —  412 open ports             │
│  [████████░░░░░░░░░░░░░░░░░░░░░░] Stage 4  —  2,156 URLs discovered      │
│  [████░░░░░░░░░░░░░░░░░░░░░░░░░░] Stage 5  —  89 services probed         │
│  [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] Stage 6  —  waiting...                 │
└───────────────────────────────────────────────────────────────────────────┘
```

### Vulnerability View

```bash
kiral vulns example.com --severity critical,high
```

| Severity | Template | Name | Asset |
|----------|----------|------|-------|
| `CRITICAL` | `cve-2024-XXXX` | Remote Code Execution | `api.example.com` |
| `HIGH` | `exposed-panel` | Admin Panel Exposed | `admin.example.com` |
| `HIGH` | `sql-injection` | SQL Injection in Parameter | `app.example.com/search` |

### System Health Check

```bash
kiral status
```

Checks every component at a glance — subfinder, dnsx, rustscan, gau, katana, httpx, nuclei, Redis, ClickHouse, and the Docker consumer — with color-coded status badges.

---

## 🏗️ Architecture

KIRAL is designed as a **distributed pipeline** with clear separation between scanning and storage:

```
┌─────────────────────────────┐                      ┌─────────────────────────────┐
│      SCAN SERVER            │    Redis Stream      │      DATA SERVER            │
│   (Laptop / Cloud VM)       │◄────────────────────►│   (Dedicated Linux Box)     │
│                             │   asm:events:v1      │                             │
│  ┌─────────────────────┐    │                      │  ┌─────────────────────┐    │
│  │  kiral scan <domain>│    │  XADD / XREADGROUP   │  │  Consumer (Docker)  │    │
│  │                     │    │                      │  │                     │    │
│  │  Stage 1: subfinder │───►│  Deduplication       │  │  Batch Ingestor     │    │
│  │  Stage 2: dnsx      │───►│  (Redis SADD)        │  │  5K events / 5s     │    │
│  │  Stage 3: rustscan  │───►│                      │  │                     │    │
│  │  Stage 4: gau+katana│───►│                      │  │  INSERT INTO        │    │
│  │  Stage 5: httpx     │───►│                      │  │  events FORMAT      │───►│
│  │  Stage 6: nuclei    │───►│                      │  │  JSONEachRow        │    │
│  └─────────────────────┘    │                      │  └─────────────────────┘    │
│                             │                      │           │                 │
│  ┌─────────────────────┐    │                      │           ▼                 │
│  │  kiral query/export │◄───┘                      │  ┌─────────────────────┐    │
│  │  kiral vulns        │◄──────────────────────────┘  │   ClickHouse        │    │
│  │  kiral dashboard    │                              │   asm_pipeline.     │    │
│  └─────────────────────┘                              │   events            │    │
│                                                       └─────────────────────┘    │
└─────────────────────────────┘                      └─────────────────────────────┘
```

**Why this design?**

- **Redis Streams** provide a durable, fault-tolerant message bus with consumer groups and pending-message recovery
- **ClickHouse** handles analytical queries over billions of rows with sub-second response times
- **Decoupled architecture** lets you run scans from your laptop while the heavy database lives on a server

---

## 📋 Command Reference

| Command | Panel | Purpose |
|---------|-------|---------|
| `kiral scan <domain>` | Operations | Launch a full 6-stage reconnaissance scan |
| `kiral status` | Operations | Health check all pipeline components |
| `kiral init` | Operations | Initialize ClickHouse database and events table |
| `kiral query <domain>` | Data | Query ClickHouse with rich table output |
| `kiral export <domain>` | Data | Export all events for a domain to a text file |
| `kiral vulns <domain>` | Data | Display vulnerability findings with severity badges |
| `kiral purge <domain>` | Data | Permanently delete scan data (`--full` clears Redis too) |
| `kiral dashboard` | Monitoring | Live pipeline monitoring dashboard |
| `kiral debug <domain>` | Monitoring | Diagnose Redis vs ClickHouse data gaps |

```bash
# Scan with a specific profile
kiral scan example.com --profile aggressive

# Query only subdomains
kiral query example.com --type SUBDOMAIN_FOUND --limit 100

# Export findings
kiral export example.com --output findings.txt

# Show only critical vulnerabilities
kiral vulns example.com --severity critical

# Purge data for a clean re-scan
kiral purge example.com --force --full
```

---

## 🔧 The 6 Stages Explained

### Stage 1 — Subdomain Enumeration
Discovers every subdomain using passive sources (Shodan, Crt.sh, VirusTotal, etc.) via **subfinder**.

### Stage 2 — DNS Resolution
Resolves every discovered subdomain to IPv4, IPv6, and CNAME records using **dnsx**.

### Stage 3 — Port Scanning
Scans the top 1,000 most common ports on every IP using **rustscan** (blazing fast with rate limiting).

### Stage 4 — URL Discovery
Expands the attack surface by discovering historical URLs via **gau** and crawling live endpoints via **katana** — no open ports required.

### Stage 5 — HTTP Probing
Probes every candidate URL with **httpx** to extract status codes, page titles, technology stacks, TLS versions, and response hashes.

### Stage 6 — Vulnerability Detection
Runs **nuclei** against all live services with JSON output and severity classification — from informational to critical.

---

## 🛡️ Safety & Resilience

- **Hard event limit:** Scans auto-abort at 500,000 events to prevent runaway execution
- **Tool timeouts:** Every subprocess has a strict timeout (3–10 minutes depending on the tool)
- **Memory guard:** Tools outputting >512 MB are killed automatically
- **Graceful shutdown:** `Ctrl+C` finishes the current stage before exiting cleanly
- **Crash recovery:** The consumer uses Redis `XCLAIM` to reclaim messages from crashed workers
- **Retry logic:** ClickHouse inserts retry up to 3 times with exponential backoff

---

## 🎨 Design Philosophy

KIRAL isn't just a tool — it's an **experience**.

- **Neon cyan** (`#00f0ff`) for active states and headers
- **Matrix green** (`#00ff41`) for completed operations and healthy status
- **Cyber amber** (`#ff9f1c`) for stealth mode and caution
- **Alert red** (`#ff0044`) for failures and critical severity
- **Plasma purple** (`#bd00ff`) for scan IDs and special badges

Every panel, every badge, every progress bar is crafted to make hours of reconnaissance feel like piloting a mission control system.

---

## 📦 Requirements

### Core (Python)
- Python 3.10+
- redis, httpx, python-dotenv, pydantic, pydantic-settings, typer, rich

### Scanning Tools (binaries in PATH)
- [subfinder](https://github.com/projectdiscovery/subfinder) — Subdomain discovery
- [dnsx](https://github.com/projectdiscovery/dnsx) — DNS toolkit
- [rustscan](https://github.com/RustScan/RustScan) — Port scanner
- [gau](https://github.com/lc/gau) — GetAllUrls (historical URLs)
- [katana](https://github.com/projectdiscovery/katana) — Web crawler
- [httpx](https://github.com/projectdiscovery/httpx) — HTTP prober *(Go binary)*
- [nuclei](https://github.com/projectdiscovery/nuclei) — Vulnerability scanner

> ⚠️ **Note:** The Python `httpx` library shadows the Go `httpx` binary in the virtual environment. Run `rm venv/bin/httpx` (Linux/Mac) or remove the script from `venv/Scripts` (Windows) after installation.

### Infrastructure
- [Redis](https://redis.io/) 6.2+ (message bus)
- [ClickHouse](https://clickhouse.com/) 23+ (analytics database)

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| [`mdfiles/CLI_GUIDE.md`](mdfiles/CLI_GUIDE.md) | Complete CLI usage guide |
| [`mdfiles/HOW_IT_WORKS.md`](mdfiles/HOW_IT_WORKS.md) | Deep dive into every network call and data flow |
| [`mdfiles/RUNBOOK.md`](mdfiles/RUNBOOK.md) | Operational runbook for production deployments |
| [`mdfiles/VPS_SETUP_GUIDE.md`](mdfiles/VPS_SETUP_GUIDE.md) | Server setup instructions |
| [`mdfiles/NUCLEI_SETUP.md`](mdfiles/NUCLEI_SETUP.md) | Nuclei installation and template updates |
| [`mdfiles/GAU_KATANA_SETUP.md`](mdfiles/GAU_KATANA_SETUP.md) | URL discovery tools setup |

---

## 🤝 Contributing

We welcome contributions! Whether it's a new recon tool integration, a UI enhancement, or documentation improvements:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-thing`)
3. Commit your changes (`git commit -am 'Add amazing thing'`)
4. Push to the branch (`git push origin feature/amazing-thing`)
5. Open a Pull Request

---

## 📜 License

KIRAL is released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">

<pre style="background: transparent; border: none;">
██╗  ██╗██╗██████╗  █████╗ ██╗     
██║ ██╔╝██║██╔══██╗██╔══██╗██║     
█████╔╝ ██║██████╔╝███████║██║     
██╔═██╗ ██║██╔══██╗██╔══██║██║     
██║  ██╗██║██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
</pre>

<p><em>Built for defenders who think like attackers.</em></p>

</div>
