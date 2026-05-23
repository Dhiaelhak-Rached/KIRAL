# ASM Pipeline — Run & Test Guide

How to bring the pipeline up and run a scan. Two machines:
- **Server** (`192.168.1.21`, user `dhia`) — hosts Redis, ClickHouse, and the consumer container.
- **Laptop** (Windows) — runs the orchestrator (subfinder/amass/dnsx/naabu/httpx) and publishes events to the server.

---

## 1. One-time setup

### Server (`192.168.1.21`)

```bash
cd /opt/asm-pipeline

# Bring up Redis + ClickHouse
docker compose up -d redis clickhouse

# Build the consumer image (only when src/ changes)
docker build -f Dockerfile.consumer -t asm-consumer .
```

### Laptop

```powershell
# Python venv
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Make sure pd-httpx (the Go recon tool) shadows venv's Python httpx CLI
$env:PATH = "C:\Users\rache\go\bin;$env:PATH"

# Verify all recon tools are reachable
foreach ($t in 'subfinder','amass','dnsx','naabu','httpx') { Get-Command $t | Select Source }
```

If any tool is missing:
```powershell
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Initialize ClickHouse schema (run once after a fresh `clickhouse_data` volume)

From the laptop:
```powershell
python -m src.init_schema --user asm_ingestor --password changeme
```

Expected: `Schema initialized successfully`. Idempotent — safe to re-run.

---

## 2. Start the pipeline (every time)

### Server — start the consumer

```bash
docker rm -f asm-consumer 2>/dev/null

docker run -d \
  --name asm-consumer \
  --restart unless-stopped \
  --network host \
  --env-file /opt/asm-pipeline/.env \
  asm-consumer

# Confirm it's healthy
sleep 3 && docker logs asm-consumer --tail 5
```

Expected last lines:
```
[INFO] src.consumer: Created consumer group ch_ingestors
[INFO] src.consumer: Ingester started
```

Why `--network host` + `--env-file`: the consumer must reach Redis with `ASM_REDIS_PASSWORD`, and ClickHouse's `asm_ingestor` only accepts the `192.168.1.0/24` source IP. Host networking gives the container the host's LAN IP.

### Laptop — verify connectivity (optional)

```powershell
# Redis reachable
Test-NetConnection 192.168.1.21 -Port 6379

# ClickHouse responds and asm_ingestor can SELECT
$pair="asm_ingestor:changeme"; $b64=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
Invoke-WebRequest "http://192.168.1.21:8123/?database=asm_pipeline" -Method Post `
  -Body "SELECT count() FROM events" -Headers @{Authorization="Basic $b64"} -UseBasicParsing | % Content
```

---

## 3. Run a scan

```powershell
# Always prepend go\bin so pd-httpx wins over Python httpx
$env:PATH = "C:\Users\rache\go\bin;$env:PATH"

# Run against a domain you own / are authorized to scan
python -m src.orchestrator dnsafe.io
```

Stages logged in order:
1. Subdomain enumeration (subfinder + amass passive, ~60s)
2. DNS resolution (dnsx)
3. Port scanning (naabu — currently capped to top-1000 ports for smoke runs; restore `-p -` in `src/scanner.py` for full sweep)
4. HTTP probing (httpx)

Last log line:
```
Scan <uuid> finished in <N>s. Total published=<count>
```

---

## 4. Verify results landed in ClickHouse

From the laptop:
```powershell
$pair="asm_ingestor:changeme"; $b64=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair)); $h=@{Authorization="Basic $b64"}
$url="http://192.168.1.21:8123/?database=asm_pipeline"

# Row counts by event type
(Invoke-WebRequest $url -Method Post -Body "SELECT event_type, count() FROM events GROUP BY event_type ORDER BY event_type FORMAT TSV" -Headers $h -UseBasicParsing).Content

# Last 10 events
(Invoke-WebRequest $url -Method Post -Body "SELECT event_type, asset, source_tool, scan_timestamp FROM events ORDER BY scan_timestamp DESC LIMIT 10 FORMAT TSV" -Headers $h -UseBasicParsing).Content

# Only the most recent scan
(Invoke-WebRequest $url -Method Post -Body "SELECT event_type, asset, source_tool FROM events WHERE scan_id=(SELECT scan_id FROM events ORDER BY scan_timestamp DESC LIMIT 1) FORMAT TSV" -Headers $h -UseBasicParsing).Content
```

Or directly on the server:
```bash
docker exec asm-clickhouse clickhouse-client --query "SELECT event_type, count() FROM asm_pipeline.events GROUP BY event_type ORDER BY event_type"
```

---

## 5. Cleanup / reset

```bash
# Wipe events between runs
docker exec asm-clickhouse clickhouse-client --query "TRUNCATE TABLE asm_pipeline.events"

# Clear Redis stream + dedup cache (drops in-flight messages too)
docker exec asm-redis redis-cli -a changeme DEL asm:events:v1 asm:dedup:seen

# Stop everything
docker rm -f asm-consumer
docker compose down
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Schema initialization failed: ClickHouse HTTP 403/500 ACCESS_DENIED` | Running `init_schema.py` with a user that lacks DDL grants | Use `--user asm_ingestor --password changeme` (current `users.xml` grants DDL to it) |
| `Authentication required` in consumer logs | Container started without `--env-file` | Use the exact `docker run` block in §2 |
| `AUTHENTICATION_FAILED: asm_ingestor` from ClickHouse despite right password | Consumer NAT'd to a non-LAN IP (172.x) outside `users.xml` allow-list | Use `--network host` (already in §2) |
| `Cannot parse input … scan_timestamp` (Code 27) | `events` table built with `DateTime` not `DateTime64(3,'UTC')` | Recreate table — see `src/init_schema.py` for canonical schema |
| `httpx -version` shows Python HTTP CLI, not projectdiscovery | venv's Python `httpx` shadows the Go binary | Prepend `C:\Users\rache\go\bin` to `PATH` |
| `ports_found=0` despite obvious open ports | Cloudflare/CDN drops SYN, or Windows naabu lacks raw-socket privs | Run terminal as Administrator, or accept that connect-scan only sees firewalled-allowed ports |

---

## Credentials reference

| Service | User | Password | Where set |
|---|---|---|---|
| ClickHouse (pipeline + DDL) | `asm_ingestor` | `changeme` | `clickhouse/users.xml`, `.env` |
| Redis | _(no user)_ | `changeme` | `configs/redis.conf`, `.env` |

**Rotate `changeme` before exposing this beyond the `192.168.1.0/24` LAN.**



  Container: asm-clickhouse
  Image: clickhouse/clickhouse-server:24.3
  Role: Long-term event store + query engine
  Used for: Holds the asm_pipeline.events table — every subdomain, DNS record, port, and
  HTTP
    service the pipeline ever finds. Partitioned by month, TTL 12 months. This is what you
    query to analyze the attack surface.
  ────────────────────────────────────────
  Container: asm-consumer
  Image: asm-consumer (built from Dockerfile.consumer)
  Role: Bridge between bus and store
  Used for: Reads batches from the Redis Stream via a consumer group, transforms them into
    ClickHouse rows, batch-inserts via JSONEachRow, then ACKs the messages. If a batch
  fails,
  ────────────────────────────────────────
  Container: asm-consumer
  Image: asm-consumer (built from Dockerfile.consumer)
  Role: Bridge between bus and store
  Used for: Reads batches from the Redis Stream via a consumer group, transforms them into ClickHouse rows, batch-inserts via JSONEachRow, then ACKs the
    messages. If a batch fails, messages stay in the pending list and get retried — that's how the pipeline survives a consumer crash without losing
    events.