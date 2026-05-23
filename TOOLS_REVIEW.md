# Tools Review — Are You Using the Best Recon Stack?

> Research date: May 2026. Based on public benchmarks, community consensus, and active maintenance status.

---

## Verdict at a Glance

| Stage | Your Current Tool | Verdict | Should You Switch? |
|-------|-------------------|---------|-------------------|
| 1a. Passive Subdomains | **subfinder** | ⭐ Still the gold standard | **No** |
| 1b. Deep Passive Subdomains | **amass** (passive) | Good but slow | **Consider BBOT** for depth |
| 2. DNS Resolution | **dnsx** | ⭐ Still the gold standard | **No** |
| 3. Port Scanning | **naabu** (top-1000) | Good for web, slow for full ranges | **Consider RustScan** for full port sweeps |
| 4. HTTP Probing | **httpx** | ⭐ Still the gold standard | **No** |
| 5. *(Missing)* Endpoint Discovery | — | High-value addition | **Add Katana** |
| 6. *(Missing)* Vuln Scanning | — | High-value addition | **Add Nuclei** |

**Bottom line:** Your stack is solid. ProjectDiscovery owns the recon pipeline in 2026. You don't need to replace anything urgently, but you can **add** tools for deeper coverage.

---

## Stage 1: Subdomain Enumeration

### subfinder — KEEP IT
- **Why:** Fastest passive enumerator. Queries 35+ sources. Zero noise. Returns valid results in seconds.
- **2026 status:** Still actively maintained. Still the #1 recommendation in every recon guide.
- **Benchmark:** Finds ~90% of what the deepest tools find in ~1/10th of the time.

### amass (passive) — KEEP IT, but know its limits
- **Why:** Finds a few unique subdomains that subfinder misses (e.g., via Maltiverse, deeper OSINT correlation).
- **The problem:** Much slower. In one benchmark, amass took **23 minutes** to collect 227 subdomains while subfinder got 500+ in 30 seconds.
- **Your fix is correct:** You run amass in **passive-only** mode (`-passive -silent`) which removes the slow active bruteforce. Keep this.

### Alternative: BBOT
- **What:** Black Lantern Security's recursive recon framework.
- **Pros:** Finds the **most** subdomains in benchmarks (including unique ones others miss). Does recursive discovery (finds subdomains of subdomains automatically). Correlates infrastructure relationships.
- **Cons:** Slower than subfinder. Higher resource usage. More complex output.
- **Verdict:** If you scan large scopes and need maximum depth, **add BBOT as a third source** alongside subfinder + amass. Don't replace subfinder.

```bash
# BBOT equivalent to your current stage 1
bbot -t example.com -p subdomain-enum -rf passive
```

---

## Stage 2: DNS Resolution

### dnsx — KEEP IT
- **Why:** Fast, clean JSON output (`-json`), supports A/AAAA/CNAME/MX/TXT/NS/SOA, response time tracking, resolver rotation.
- **2026 status:** No better open-source alternative exists. PureDNS exists but requires massdns + resolver lists — more complex for marginal gain.
- **Your usage is perfect:** Input file (`-l`), JSON output (`-json`), multiple record types (`-a -aaaa -cname`).

### Optional Enrichment: tlsx
- **What:** ProjectDiscovery tool for TLS certificate grabbing.
- **Value:** Discovers subdomains from SSL/TLS certificates (SNI, alt names) that DNS tools miss.
- **Verdict:** Nice-to-have. Can be added as a small parallel stage:
```bash
echo example.com | tlsx -san -cn -json
```

---

## Stage 3: Port Scanning

### naabu — GOOD, but limited
- **Why you picked it:** Go-based, stable, JSON output, integrates with PD ecosystem, supports DNS resolution + IP dedup, can query Shodan passively (`-passive`), pipes nicely into nmap.
- **Your current command:** `-top-ports 1000` — this is fast but misses obscure ports.

### The Speed Problem
| Tool | Time to scan all 65,535 ports | Notes |
|------|------------------------------|-------|
| **naabu** | Not designed for full range | Best for targeted top-ports |
| **RustScan** | ~3 seconds | Rust-based, raw speed king |
| **masscan** | ~5 seconds | C-based, internet-scale proven |
| **nmap** | ~20+ minutes | Accurate but slow |

### Alternative: RustScan
- **Pros:** Scans **all 65,535 ports in ~3 seconds**. Adaptive learning. Scripting engine (can auto-pipe to nmap for service detection).
- **Cons:** No built-in JSON output (needs parsing). No DNS resolution. No Shodan integration. Less "pipeline-native" than naabu.
- **Verdict:** If you need **full port coverage** (not just top-1000), **replace naabu with RustScan** for the discovery phase, then optionally run nmap on found ports. If you only care about common web ports, keep naabu.

### Recommended Hybrid Approach
```bash
# Fast full-range discovery
rustscan -a <ip> --range 1-65535 -g | \
  # Then service detection on found ports
  nmap -sV -sC -p <ports> <ip>
```

Or keep naabu for quick smoke tests and add RustScan as an optional "deep scan" mode.

---

## Stage 4: HTTP Probing

### httpx — KEEP IT, PERIOD
- **Why:** Multi-purpose HTTP toolkit. Status codes, titles, tech detection, headers, TLS version, response hashes, CDN detection, follow-redirects, screenshots, JARM fingerprints.
- **2026 status:** Absolutely zero competition in the open-source space for this specific job.
- **Your usage is good** but you could enable a few more flags for richer data:
```bash
httpx -l urls.txt -silent -json -o - \
  -tech-detect -title -status-code \
  -follow-redirects -asn -cdn \
  -jarm -hash sha256
```

---

## What You're Missing (High-Value Additions)

### Stage 5: Web Crawling / Endpoint Discovery — Add Katana
**Current gap:** `httpx` only probes the URLs you give it. It does NOT crawl links or discover new endpoints.

**Katana** (ProjectDiscovery) fills this gap:
- Crawls websites and extracts ALL endpoints (links, JS files, API paths, forms).
- **Headless mode** (`-headless`) renders SPAs (React, Angular) and captures XHR/Fetch requests.
- Extracts JavaScript endpoints that static analysis misses.
- JSONL output for pipeline integration.

**Why it matters:** You might probe `https://api.example.com` and get a 200, but Katana discovers `/api/v1/users`, `/api/v1/admin`, `/graphql`, etc.

```bash
# Basic crawl
katana -u https://example.com -jc -jsl -jsonl -silent

# Headless for modern SPAs
katana -u https://example.com -headless -jc -xhr -jsonl -silent

# Pipeline integration
subfinder -d example.com -silent | httpx -silent | katana -jc -jsonl
```

### Stage 6: Vulnerability Scanning — Add Nuclei
**Current gap:** You discover assets but don't test them for known vulnerabilities.

**Nuclei** (ProjectDiscovery) is the industry-standard template scanner:
- 9,000+ community templates for CVEs, misconfigurations, exposed panels, default creds.
- Fast, low-noise, YAML-based templates.
- JSON output for pipeline ingestion.
- Can run against your live URLs after httpx.

```bash
# Basic usage
cat live_urls.txt | nuclei -severity low,medium,high,critical -jsonl -o findings.jsonl

# Template examples it can detect:
# - Exposed .env files, Git repos, backup files
# - Default admin panels (phpMyAdmin, WordPress, etc.)
# - Known CVEs (Log4j, Spring4Shell, etc.)
# - Misconfigured headers, CORS, SSL issues
```

### Optional: gau (GetAllUrls)
- **What:** Queries Wayback Machine, Common Crawl, AlienVault OTX for **historical URLs**.
- **Value:** Finds endpoints that existed in the past but aren't linked anymore (old APIs, deleted pages).
- **Verdict:** Lightweight and useful. Good addition before Katana.
```bash
echo example.com | gau --threads 5
```

---

## Recommended Updated Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         STAGE 1: DISCOVERY                              │
├─────────────────────────────────────────────────────────────────────────┤
│  subfinder  →  amass (passive)  →  [optional: BBOT]                     │
│       ↓                                                                 │
│                         STAGE 2: RESOLUTION                             │
├─────────────────────────────────────────────────────────────────────────┤
│  dnsx  →  [optional: tlsx]                                              │
│       ↓                                                                 │
│                         STAGE 3: PORT SCANNING                          │
├─────────────────────────────────────────────────────────────────────────┤
│  naabu (top-1000)  →  [optional: RustScan (full range)]                 │
│       ↓                                                                 │
│                         STAGE 4: HTTP PROBING                           │
├─────────────────────────────────────────────────────────────────────────┤
│  httpx (enriched: -asn -cdn -jarm -hash)                                │
│       ↓                                                                 │
│                         STAGE 5: CRAWLING + ENDPOINTS                   │
├─────────────────────────────────────────────────────────────────────────┤
│  gau (historical)  →  katana (crawl + JS endpoints)                     │
│       ↓                                                                 │
│                         STAGE 6: VULNERABILITY SCANNING                 │
├─────────────────────────────────────────────────────────────────────────┤
│  nuclei                                                                 │
│       ↓                                                                 │
│                    ALL EVENTS → Redis → ClickHouse                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Action Items for Your Codebase

### Immediate (no-brainers)
1. **Keep:** subfinder, dnsx, httpx.
2. **Add Katana** as Stage 5 — highest ROI addition. Just a new method in `scanner.py` + a normalizer parser.
3. **Add Nuclei** as Stage 6 — turns your pipeline from "recon" into "attack surface monitoring."

### Optional (evaluate)
4. **Add BBOT** alongside amass if you need deeper subdomain discovery.
5. **Replace naabu** with RustScan only if you need full 1-65535 port coverage.
6. **Add tlsx** for SSL/TLS certificate subdomain enumeration.
7. **Add gau** for historical URL discovery before Katana.

### What NOT to do
- Don't replace subfinder with anything. It's still #1.
- Don't replace dnsx. It's the standard.
- Don't replace httpx. Nothing beats it for HTTP probing.
- Don't switch amass to active mode. Active bruteforce is extremely slow and noisy.

---

## Installation Commands for New Tools

```bash
# Katana (web crawler)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Nuclei (vulnerability scanner)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# BBOT (deep recon framework)
pipx install bbot

# RustScan (fast full-range port scanner)
cargo install rustscan
# or
docker run -it --rm rustscan/rustscan:2.1.1

# tlsx (TLS certificate grabber)
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# gau (historical URLs)
go install github.com/lc/gau/v2/cmd/gau@latest
```

---

## Sources & Benchmarks Referenced

- [Port Scanner Shootout — Naabu vs RustScan vs Nmap](https://s0cm0nkey.gitbook.io/port-scanner-shootout/)
- [Subdomain Enumeration Tool Face-off — BBOT vs Subfinder vs Amass](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)
- [ProjectDiscovery Official Docs — 2026](https://docs.projectdiscovery.io/)
- [Bug Bounty Hunter Software Stack 2026 — Penligent](https://www.penligent.ai/hackinglabs/bug-bounty-hunter-software-in-2026/)
- [Best Open-Source Web Crawlers 2026 — Firecrawl](https://www.firecrawl.dev/blog/best-open-source-web-crawler)
- [pentest-book Tool Reviews — 2025 Update](https://github.com/six2dez/pentest-book/blob/master/others/subdomain-tools-review.md)
