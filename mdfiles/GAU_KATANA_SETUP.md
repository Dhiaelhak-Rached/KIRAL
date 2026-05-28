# gau + katana Setup Guide

> Install URL Discovery tools for Stage 4 of the KIRAL pipeline.
>
> These tools run **locally on the Linux scan server** alongside subfinder, dnsx, rustscan, httpx, and nuclei.

---

## What Are These Tools?

| Tool | Purpose | Source |
|------|---------|--------|
| **gau** (GetAllUrls) | Fetches **historical URLs** from Wayback Machine, CommonCrawl, and AlienVault OTX | Passive |
| **katana** | **Headless crawler** that discovers JavaScript-rendered endpoints, API paths, hidden parameters | Active |

**Combined effect:** `gau` finds URLs that *used to exist* (and may still work). `katana` finds URLs that are *hidden* behind JavaScript or not linked from the main site. Together they typically expand the attack surface by **10-50x**.

---

## Installing gau

### Method 1: Binary Release (Recommended)

```bash
# Download the latest Linux AMD64 release
curl -s https://api.github.com/repos/lc/gau/releases/latest | \
  grep "browser_download_url.*linux_amd64" | cut -d '"' -f 4 | wget -qi -

# Extract to /usr/local/bin
sudo tar -xzf gau_*_linux_amd64.tar.gz -C /usr/local/bin/
rm gau_*_linux_amd64.tar.gz

# Verify
gau --version
```

### Method 2: Go Install

If you already have Go installed:

```bash
go install github.com/lc/gau/v2/cmd/gau@latest

# Ensure ~/go/bin is in your PATH
export PATH="$HOME/go/bin:$PATH"
```

---

## Installing katana

### Method 1: Binary Release (Recommended)

```bash
# Download the latest Linux AMD64 release
curl -s https://api.github.com/repos/projectdiscovery/katana/releases/latest | \
  grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4 | wget -qi -

# Extract to /usr/local/bin
sudo unzip katana_*_linux_amd64.zip -d /usr/local/bin/
rm katana_*_linux_amd64.zip

# Verify
katana -version
```

### Method 2: Go Install

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Ensure ~/go/bin is in your PATH
export PATH="$HOME/go/bin:$PATH"
```

---

## Verify Installation

```bash
# Check binaries are in PATH
which gau
which katana

# Check versions
gau --version
katana -version

# Quick smoke tests
gau --subs --o - scanme.nmap.org | head -5
katana -u https://scanme.nmap.org -silent -headless -jsonl | head -5
```

---

## KIRAL Integration

Once installed, KIRAL automatically uses them as **Stage 4** during every scan.

### What happens during a scan

1. **Stage 3** (`rustscan`) discovers open ports.
2. **Stage 4** (`gau` + `katana`) runs concurrently:
   - `gau` fetches historical URLs for the target domain and all discovered subdomains.
   - `katana` crawls the discovered subdomains to find JS endpoints and API paths.
3. All discovered URLs are deduplicated and merged with port-based URLs.
4. **Stage 5** (`httpx`) probes the combined URL list (original + discovered).
5. **Stage 6** (`nuclei`) scans all discovered services for vulnerabilities.

### CLI commands that use URL Discovery

```bash
# Run a full 6-stage scan
kiral scan example.com

# Check that gau and katana are detected
kiral status
# → gau    │  OK  │ /usr/local/bin/gau
# → katana │  OK  │ /usr/local/bin/katana

# Query discovered URLs
kiral query example.com --type URL_DISCOVERED --limit 50

# Export everything including discovered URLs
kiral export example.com
```

---

## Configuration

No special `.env` configuration is needed. Both tools run as local binaries, just like `subfinder` or `httpx`.

If you want to tune behavior, edit the method in `src/scanner.py`:

```python
# gau timeout (default: 180 seconds = 3 minutes)
async for finding in self.runner.run(cmd, target, timeout_sec=180):

# katana timeout (default: 300 seconds = 5 minutes)
async for finding in self.runner.run(cmd, target, timeout_sec=300):
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `gau: command not found` | Not in `$PATH` | Ensure `/usr/local/bin` or `~/go/bin` is in PATH |
| `katana: command not found` | Not in `$PATH` | Same as above |
| `kiral status` shows ERROR | Wrong binary or not installed | Run `which gau` and `which katana` |
| Stage 4 completes with 0 URLs | Target has no historical data | Normal for brand-new domains |
| katana hangs | Headless mode on resource-constrained server | Reduce `-concurrency` in `scanner.py` |
| Permission denied extracting | `/usr/local/bin` requires sudo | Use `sudo tar ...` or install to `~/bin` |
| gau produces no output | Network blocks or no historical data | Try with `--verbose` flag manually |

---

## One-Liner Verification

```bash
gau --version && katana -version && \
  gau --subs --o - scanme.nmap.org | wc -l && \
  katana -u https://scanme.nmap.org -silent -jsonl | wc -l
```

Expected output:
- Both version commands succeed
- gau returns a number ≥ 0
- katana returns a number ≥ 0

Then run:

```bash
kiral status
```

Both `gau` and `katana` should show **[OK]** in green.
