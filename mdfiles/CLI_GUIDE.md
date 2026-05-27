# KIRAL CLI Guide

> The **Dark Intelligence Terminal** for your Attack Surface Management pipeline.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [`kiral scan`](#kiral-scan)
  - [`kiral status`](#kiral-status)
  - [`kiral init`](#kiral-init)
  - [`kiral query`](#kiral-query)
  - [`kiral export`](#kiral-export)
  - [`kiral dashboard`](#kiral-dashboard)
- [Visual Theme](#visual-theme)
- [Troubleshooting](#troubleshooting)

---

## Installation

### 1. Ensure dependencies are installed

```bash
pip install -r requirements.txt
```

This installs `typer` and `rich` alongside the existing pipeline dependencies.

### 2. (Optional) Install as a proper command

```bash
\
```

This registers `kiral` as a global command. Otherwise, use `python -m src.cli` or the provided `kiral.bat` (Windows).

### 3. Windows users — UTF-8 support

The CLI uses box-drawing characters for its gorgeous tables and panels. If you see garbled borders, set:

```powershell
$env:PYTHONIOENCODING = "utf-8"
```

Or run via the provided batch script which handles this automatically:

```powershell
.\kiral.bat status
```

---

## Quick Start

```bash
# Check that everything is healthy
kiral status

# Initialize the database (one-time)
kiral init -u asm_ingestor -p changeme

# Run your first reconnaissance scan
kiral scan example.com

# Query what was found
kiral query example.com --limit 20

# Export everything to a file
kiral export example.com -o my_report.txt
```

---

## Commands

### `kiral scan`

Run the full 4-stage reconnaissance pipeline with a **live dashboard**.

```bash
kiral scan <domain>
kiral scan example.com
kiral scan example.com --profile aggressive
```

**What you see:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│                    ██╗  ██╗██╗██████╗  █████╗ ██╗                           │
│                    ██║ ██╔╝██║██╔══██╗██╔══██╗██║                           │
│                    █████╔╝ ██║██████╔╝███████║██║                           │
│                    ██╔═██╗ ██║██╔══██╗██╔══██║██║                           │
│                    ██║  ██╗██║██║  ██║██║  ██║███████╗                      │
│                    ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝                      │
│                    Attack Surface Intelligence Terminal                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────── Mission Configuration ───────────────────────────┐
│                                                                             │
│        Target    example.com                                                │
│       Profile    STEALTH                                                    │
│       Scan ID    a1b2c3d4-...                                               │
│         Redis    192.168.1.21                                               │
│    ClickHouse    http://192.168.1.21:8123                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─ KIRAL Reconnaissance Pipeline ─────────────────────────────────────────────┐
│                                                                             │
│  Target: example.com  │  Profile: STEALTH  │  Scan ID: a1b2c3d4            │
│                                                                             │
│  ▶ Stage 1/4: Subdomain Enumeration  -------  47%  │  1,247 found  │ running│
│  ⏸ Stage 2/4: DNS Resolution                      0%  │  0 found  │ waiting │
│  ⏸ Stage 3/4: Port Scanning                       0%  │  0 found  │ waiting │
│  ⏸ Stage 4/4: HTTP Probing                        0%  │  0 found  │ waiting │
│                                                                             │
│  Published: 3,421  │  Events/sec: 142  │  Elapsed: 02:14                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Stages:**
1. **Subdomain Enumeration** (`subfinder`) — discovers subdomains
2. **DNS Resolution** (`dnsx`) — resolves subdomains to IPs
3. **Port Scanning** (`rustscan`) — finds open ports
4. **HTTP Probing** (`httpx`) — detects services, titles, technologies

**When the scan finishes**, a rich summary table appears:

```
                    Scan Complete
┌────────────────┬────────┐
│ Metric         │ Value  │
├────────────────┼────────┤
│ Subdomains     │  1,247 │
│ Unique IPs     │    892 │
│ Candidate URLs │  4,521 │
│ Total Events   │  8,934 │
│ Duration       │ 05:32  │
└────────────────┴────────┘
```

**Options:**

| Flag | Description |
|------|-------------|
| `--profile stealth` | Top-1000 ports, low concurrency (default) |
| `--profile aggressive` | Full 1-65535 port range, high concurrency |

---

### `kiral status`

Check the health of every component in one glance.

```bash
kiral status
```

**Output:**

```
┌─ System Status ─────────────────────────────────────────────────────────────┐
│  ┌────────────┬─────────────┬────────────────────────────────────────────┐  │
│  │ Redis      │  CONNECTED  │ 192.168.1.21:6379  v7.4.9                  │  │
│  │ ClickHouse │  CONNECTED  │ http://192.168.1.21:8123 — asm_pipeline OK │  │
│  │ subfinder  │  OK         │ C:\Users\...\subfinder.EXE                 │  │
│  │ dnsx       │  OK         │ C:\Users\...\dnsx.EXE                      │  │
│  │ rustscan   │  OK         │ C:\Users\...\rustscan.EXE                  │  │
│  │ httpx      │  OK         │ C:\Users\...\httpx.EXE                     │  │
│  │ Consumer   │  RUNNING    │ asm-consumer (docker)                      │  │
│  └────────────┴─────────────┴────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

Status badges are color-coded:
- 🟢 **CONNECTED / OK / RUNNING / COMPLETED** — Green
- 🟡 **WAITING / IDLE / STEALTH** — Amber
- 🔴 **FAILED / ERROR / DISCONNECTED / AGGRESSIVE** — Red
- 🔵 **ACTIVE** — Cyan

---

### `kiral init`

Initialize the ClickHouse database and `events` table with visual feedback.

```bash
# Uses defaults from .env
kiral init

# Or specify credentials explicitly
kiral init -u asm_ingestor -p changeme
```

**What happens:**
1. Animated spinner: "Connecting to ClickHouse"
2. Animated spinner: "Creating database asm_pipeline"
3. Animated spinner: "Creating table events"
4. Animated spinner: "Verifying schema"
5. ✅ **COMPLETED** — Schema initialized successfully.

> **Note:** This is idempotent. Running it again is safe.

---

### `kiral query`

Query scan results from ClickHouse in a beautiful table.

```bash
# Show everything for a domain
kiral query example.com

# Filter by event type
kiral query example.com --type SUBDOMAIN_FOUND

# Limit results
kiral query example.com --limit 10
```

**Event types you can filter by:**
- `SUBDOMAIN_FOUND`
- `DNS_RESOLVED`
- `PORT_FOUND`
- `SERVICE_DETECTED`

The `Data` column shows pretty-printed JSON with syntax highlighting.

---

### `kiral export`

Export all ClickHouse events for a domain to a formatted text file.

```bash
# Default filename: <domain>_export.txt
kiral export example.com

# Custom filename
kiral export example.com -o my_report.txt
```

**What the file looks like:**

```text
Domain Export: example.com
Generated at:  2026-05-25 15:38:00
Total rows:    8,934
============================================================

--- Row 1 ---
asset               : www.example.com
data                : {
  "subdomain": "www.example.com",
  "source": "passive",
  ...
}
event_id            : ...
event_type          : SUBDOMAIN_FOUND
source_tool         : subfinder
...
```

---

### `kiral dashboard`

Launch a **live fullscreen monitor** that auto-refreshes every 2 seconds.

```bash
kiral dashboard

# Faster refresh
kiral dashboard --refresh 1
```

**Layout:**

```
┌─ KIRAL Dashboard  15:38:00 ─────────────────────────────────────────────────┐
│                                                                             │
│  ┌─ Pipeline Stats ───────────────┐  ┌─ Recent Events ───────────────────┐  │
│  │  Redis Stream Depth   12       │  │  Time  │ Type       │ Asset       │  │
│  │  Consumer Pending      0       │  │  ...   │ SUBDOMAIN  │ api...      │  │
│  │                                │  │  ...   │ DNS_RESOL  │ api...      │  │
│  │  ClickHouse Total   8,934      │  │  ...   │ PORT_FOUND │ 93.184...   │  │
│  │    DNS_RESOLVED     2,100      │  │  ...   │ SERVICE_D  │ https://    │  │
│  │    PORT_FOUND       1,500      │  └──────────────────────────────────┘  │
│  │    SERVICE_DETECTED 3,834      │                                       │
│  │    SUBDOMAIN_FOUND  1,500      │                                       │
│  └────────────────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

Press **Ctrl+C** to exit.

---

## Visual Theme

The CLI uses a cyberpunk-infused "Dark Intelligence Terminal" aesthetic:

| Color | Hex | Usage |
|-------|-----|-------|
| Primary | `#00f0ff` | Headers, borders, active spinners |
| Success | `#00ff41` | Completed stages, healthy checks |
| Warning | `#ff9f1c` | Stealth profile, idle states |
| Error | `#ff0044` | Failures, aggressive profile |
| Accent | `#bd00ff` | Scan IDs, badges |
| Muted | `#8a8f98` | Secondary text, timestamps |

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| Garbled box characters | Terminal encoding not UTF-8 | `set PYTHONIOENCODING=utf-8` or use `kiral.bat` |
| `httpx` shows ERROR in status | Python `httpx` shadows Go binary | Prepend Go bin to PATH: `$env:PATH = "C:\Users\rache\go\bin;$env:PATH"` |
| Scan shows 0 events | Deduplication cache still has old hashes | Redis dedup expires after 7 days, or clear it manually |
| ClickHouse connection fails | Wrong credentials / network | Check `.env` values and `kiral status` |
| Consumer shows WAITING | Docker container not running | Start it per `RUNBOOK.md` |

---

## One-Liner Cheat Sheet

```bash
# Full workflow
kiral status && kiral init && kiral scan example.com && kiral query example.com

# Quick health check
kiral status

# Aggressive scan
kiral scan example.com --profile aggressive

# Export latest scan
kiral export example.com

# Monitor pipeline in real-time
kiral dashboard
```
