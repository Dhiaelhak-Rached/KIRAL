# Nuclei Setup Guide

> How to install and configure Nuclei as Stage 5 of the KIRAL pipeline.
>
> Nuclei runs **locally on the scan server** alongside subfinder, dnsx, rustscan, and httpx.

---

## What is Nuclei?

Nuclei is a fast, template-based vulnerability scanner from ProjectDiscovery. It detects:

- **CVEs** — known vulnerabilities with published exploits
- **Misconfigurations** — exposed panels, default credentials, leaky headers
- **Exposures** — sensitive files, backup archives, debug endpoints
- **Technology-specific bugs** — WordPress, Apache, Nginx, etc.

Nuclei uses **templates** — YAML files that define how to detect a specific vulnerability. The community maintains thousands of them.

---

## Installation

### Method 1: Binary Release (Recommended)

```bash
# Download the latest Linux AMD64 release
curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | \
  grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4 | wget -qi -

# Extract to /usr/local/bin
sudo unzip nuclei_*_linux_amd64.zip -d /usr/local/bin/
rm nuclei_*_linux_amd64.zip

# Verify
nuclei -version
```

### Method 2: Go Install

If you already have Go installed:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Ensure ~/go/bin is in your PATH
export PATH="$HOME/go/bin:$PATH"
```

---

## Download / Update Templates

**This step is critical.** Nuclei does nothing without templates.

```bash
# Download or update the community template repository
nuclei -ut

# Verify templates are present
nuclei -nt
# Expected: thousands of templates listed (e.g., 8000+)
```

Templates are stored in `~/.nuclei-templates/` by default.

To update templates later:

```bash
nuclei -ut
```

---

## Verify Installation

```bash
# Check binary
which nuclei
# → /usr/local/bin/nuclei

# Check version
nuclei -version
# → [INF] Nuclei Engine Version: v3.x.x

# Check templates
nuclei -nt | head -5
# → [INF] Listing available nuclei templates...
# → ...

# Quick smoke test against a known target
nuclei -u https://scanme.nmap.org -silent -jsonl -severity high,critical
```

---

## KIRAL Integration

Once Nuclei is installed, KIRAL automatically uses it as **Stage 5** during every scan.

### What happens during a scan

1. **Stage 4** (`httpx`) probes all candidate URLs and discovers live services.
2. **Stage 5** (`nuclei`) takes those live service URLs and scans them for vulnerabilities.
3. Each finding is normalized to a `VULNERABILITY_FOUND` event.
4. Events flow through Redis → Consumer → ClickHouse, just like Stages 1–4.

### CLI commands that use Nuclei

```bash
# Run a full 5-stage scan
kiral scan example.com

# Check that nuclei is detected
kiral status
# → nuclei  │  OK  │ /usr/local/bin/nuclei

# Query vulnerability results
kiral query example.com --type VULNERABILITY_FOUND --limit 20

# Export everything including vulnerabilities
kiral export example.com
```

---

## Configuration

No special configuration is needed in `.env` for Nuclei itself. It runs as a local binary, just like `subfinder` or `httpx`.

The only relevant `.env` variables are the existing ones that point to Redis and ClickHouse on the Data Server:

```bash
ASM_REDIS_HOST=192.168.1.21
ASM_CH_URL=http://192.168.1.21:8123/
```

Nuclei severity is hardcoded to `low,medium,high,critical` in `src/scanner.py`. Info-level findings are skipped to reduce noise. Edit the `nuclei()` method if you want to change this.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `nuclei: command not found` | Not in `$PATH` | Ensure `/usr/local/bin` or `~/go/bin` is in PATH |
| `kiral status` shows nuclei as ERROR | Wrong binary or not installed | Run `which nuclei` and `nuclei -version` |
| Stage 5 completes with 0 findings | Templates missing or outdated | Run `nuclei -ut` |
| Nuclei hangs indefinitely | Too many URLs or slow targets | Stage 5 has a 10-minute timeout; check target size |
| Permission denied extracting binary | `/usr/local/bin` requires sudo | Use `sudo unzip ...` or install to `~/bin` instead |
| Results only show critical/high | Severity filter excludes low | This is by design — edit `-severity` in `scanner.py` to include `info` |

---

## One-Liner Verification

```bash
nuclei -ut && nuclei -version && nuclei -nt | wc -l
```

Expected output:
- `nuclei -ut` → finishes without errors
- `nuclei -version` → shows version v3.x.x
- `nuclei -nt | wc -l` → returns a large number (thousands of templates)

Then run:

```bash
kiral status
```

`nuclei` should show **[OK]** in green.
