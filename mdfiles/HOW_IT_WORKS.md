# How the ASM Pipeline Works — Complete Guide

> **In plain English.** Every step, every network call, every Redis command, and every ClickHouse query explained simply.

---

## 1. The Big Picture (What Does This Thing Do?)

This pipeline **scans a domain** (like `example.com`) to discover everything attackers could see — subdomains, IP addresses, open ports, and web services. It then **stores everything in a database** so you can search it later.

Think of it like a factory assembly line:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   STAGE 1   │ ──► │   STAGE 2   │ ──► │   STAGE 3   │ ──► │   STAGE 4   │
│  Subdomains │     │     DNS     │     │    Ports    │     │    HTTP     │
│  (subfinder)│     │   (dnsx)    │     │   (naabu)   │     │   (httpx)   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │                   │
       └───────────────────┴───────────────────┴───────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │      Redis Stream           │
                    │   (temporary waiting room)  │
                    │      Key: asm:events:v1     │
                    └─────────────────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │    Consumer / Ingester      │
                    │   (reads & transforms)      │
                    └─────────────────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │       ClickHouse            │
                    │    (permanent database)     │
                    │   Table: asm_pipeline.events│
                    └─────────────────────────────┘
```

**Two machines work together:**
- **Your Laptop (Windows)** — Runs the scanning tools and pushes results to the server.
- **Server (`192.168.1.21`)** — Runs Redis (message bus) and ClickHouse (database). The Consumer also runs here.

---

## 2. The Four Scanning Stages

When you run:
```bash
python -m src.orchestrator example.com
```

The pipeline executes **4 stages sequentially**. Each stage feeds data into the next.

---

### Stage 1: Subdomain Enumeration
**Goal:** Find every subdomain of `example.com`.

**What runs:**
- `subfinder -d example.com -all -silent -o -`

**What happens step by step:**
1. The `Scanner` class in `src/scanner.py` spawns `subfinder` as a subprocess.
2. `subfinder` queries public APIs and passive sources (Shodan, Crt.sh, VirusTotal, etc.) for subdomains.
3. Each line of output is one subdomain, e.g.:
   ```
   www.example.com
   api.example.com
   mail.example.com
   ```
4. The `ToolRunner` reads stdout **line by line** as an async stream.
5. Each line becomes a `RawFinding` object:
   ```python
   RawFinding(
       tool="subfinder",
       target="example.com",
       raw_line="www.example.com",
       timestamp="2026-05-23 01:30:00.000"
   )
   ```
6. These `RawFinding` objects flow into `_process_findings()`.
7. The `EventNormalizer` converts each into a **canonical event**:
   ```json
   {
     "event_id": "uuid-here",
     "event_type": "SUBDOMAIN_FOUND",
     "target": "example.com",
     "asset": "www.example.com",
     "source_tool": "subfinder",
     "scan_id": "scan-uuid-here",
     "scan_timestamp": "2026-05-23 01:30:00.000",
     "data": {
       "subdomain": "www.example.com",
       "source": "passive",
       "is_wildcard": false
     },
     "metadata": {
       "producer_host": "laptop-001",
       "producer_version": "0.1.0"
     }
   }
   ```
8. The `Deduplicator` checks if this exact subdomain was seen before (see §5).
9. If it's new, the `RedisEventProducer` publishes it to Redis.
10. The subdomain is saved to `self.subdomains` for Stage 2.

**Safety limits:** If the scan somehow produces more than 500,000 events, it aborts immediately to prevent runaway execution.

---

### Stage 2: DNS Resolution
**Goal:** Turn every discovered subdomain into IP addresses.

**What runs:**
- `dnsx -l subdomains.txt -a -aaaa -cname -resp -json -o -`

**What happens step by step:**
1. The orchestrator takes all subdomains found in Stage 1 (e.g., 500 subdomains) and writes them to a temporary text file.
2. `dnsx` reads that file and resolves each subdomain.
3. Output is JSON, one line per DNS response:
   ```json
   {"host":"www.example.com","a":["93.184.216.34"],"response_time_ms":12}
   ```
4. The normalizer (`_parse_dnsx`) creates one event **per record type**:
   - One event for `A` records (IPv4)
   - One event for `AAAA` records (IPv6)
   - One event for `CNAME` records (aliases)
5. Example canonical event:
   ```json
   {
     "event_type": "DNS_RESOLVED",
     "asset": "www.example.com",
     "data": {
       "hostname": "www.example.com",
       "record_type": "A",
       "resolved_values": ["93.184.216.34"],
       "resolver_used": "1.1.1.1",
       "response_time_ms": 12
     }
   }
   ```
6. All new events are deduplicated and published to Redis.
7. Every `A` record IP is saved to `self.ips` for Stage 3.

---

### Stage 3: Port Scanning
**Goal:** Find open ports on every IP discovered.

**What runs:**
- `naabu -list ips.txt -top-ports 1000 -silent -json -o - -rate 1000`

**What happens step by step:**
1. All unique IPs from Stage 2 are written to a temporary file.
2. `naabu` scans the top 1,000 most common ports on each IP.
3. Output is JSON, one line per open port:
   ```json
   {"ip":"93.184.216.34","port":443,"protocol":"tcp","scan_type":"connect"}
   ```
4. The normalizer creates a `PORT_FOUND` event:
   ```json
   {
     "event_type": "PORT_FOUND",
     "asset": "93.184.216.34:443",
     "data": {
       "ip": "93.184.216.34",
       "port": 443,
       "protocol": "tcp",
       "scan_type": "connect"
     }
   }
   ```
5. Events are deduplicated, published to Redis.
6. For each open port, the orchestrator builds candidate URLs for Stage 4:
   - Port 443 → `https://<ip>`
   - Port 80 → `http://<ip>`
   - Other ports → `http://<ip>:port` and `https://<ip>:port`

---

### Stage 4: HTTP Probing
**Goal:** Discover what web services are running and grab details (status code, title, technologies, headers).

**What runs:**
- `httpx -l urls.txt -silent -json -o - -tech-detect -title -status-code -threads 50`

**What happens step by step:**
1. The orchestrator builds a URL list from:
   - All IPs + ports from Stage 3
   - All subdomains from Stage 1 (with common web ports: 80, 443, 8080, 8443)
2. URLs are deduplicated (e.g., `https://93.184.216.34` and `https://www.example.com` might be the same server).
3. URLs are processed in chunks of 5,000 to avoid overwhelming `httpx`.
4. `httpx` probes each URL and outputs rich JSON:
   ```json
   {
     "url": "https://www.example.com",
     "host": "www.example.com",
     "ip": "93.184.216.34",
     "port": 443,
     "scheme": "https",
     "status_code": 200,
     "title": "Example Domain",
     "tech": ["Amazon S3", "React"],
     "headers": {"server": "ECS", "content-type": "text/html"},
     "tls_version": "tls1.3",
     "body_sha256": "abc123..."
   }
   ```
5. The normalizer creates a `SERVICE_DETECTED` event:
   ```json
   {
     "event_type": "SERVICE_DETECTED",
     "asset": "https://www.example.com",
     "data": {
       "url": "https://www.example.com",
       "host": "www.example.com",
       "ip": "93.184.216.34",
       "port": 443,
       "scheme": "https",
       "status_code": 200,
       "title": "Example Domain",
       "technologies": ["Amazon S3", "React"],
       "headers": {"server": "ECS", "content-type": "text/html"},
       "tls_version": "tls1.3",
       "response_hash_sha256": "abc123..."
     }
   }
   ```
6. Events are deduplicated and published to Redis.

---

## 3. All Redis Communications (Exact Commands)

Redis acts as a **message bus** — a temporary highway between the laptop and the database.

### 3.1 Connection Setup
Both the orchestrator (laptop) and the consumer (server) connect to Redis using:
```python
redis.Redis(
    host="192.168.1.21",
    port=6379,
    password="changeme",
    db=0,
    socket_connect_timeout=10,
    socket_keepalive=True,
    health_check_interval=30,
)
```

### 3.2 Publishing Events (Orchestrator → Redis)
**File:** `src/producer.py`

When the orchestrator wants to send an event, it runs this Redis command:
```
XADD asm:events:v1 MAXLEN ~ 1000000 * payload <json_string>
```

**What this means:**
- `XADD` — Add a message to a Redis Stream.
- `asm:events:v1` — The name of the stream (like a queue/topic).
- `MAXLEN ~ 1000000` — Keep roughly 1,000,000 messages max (old ones auto-delete).
- `*` — Let Redis auto-generate the message ID (timestamp-based).
- `payload` — The field name.
- `<json_string>` — The canonical event as a compact JSON string.

**Example actual call:**
```python
await redis.xadd(
    "asm:events:v1",
    {"payload": '{"event_type":"SUBDOMAIN_FOUND","asset":"www.example.com",...}'},
    maxlen=1_000_000,
    approximate=True,
)
```

**What comes back:** A message ID like `1716420000000-0`.

---

### 3.3 Deduplication (Orchestrator ↔ Redis)
**File:** `src/normalizer.py` (class `Deduplicator`)

Before publishing, the orchestrator asks Redis: *"Have we seen this exact finding before?"*

**How it works:**
1. A deterministic hash (SHA256) is computed from the event's content:
   - For `SUBDOMAIN_FOUND`: `sha256("sub:www.example.com")`
   - For `DNS_RESOLVED`: `sha256("dns:www.example.com:A:93.184.216.34")`
   - For `PORT_FOUND`: `sha256("port:93.184.216.34:443:tcp")`
   - For `SERVICE_DETECTED`: `sha256("svc:https://www.example.com:200")`

2. Redis command executed:
   ```
   SADD asm:dedup:seen <hash>
   ```
   - `SADD` — Add to a Set (collection of unique values).
   - Returns `1` if the hash was **new** (not a duplicate).
   - Returns `0` if the hash **already existed** (duplicate — skip it).

3. If it was new, set an expiration so the set doesn't grow forever:
   ```
   EXPIRE asm:dedup:seen 604800
   ```
   (604,800 seconds = 7 days)

**If Redis is down:** The deduplicator "fails open" — it allows the event through rather than blocking the pipeline.

---

### 3.4 Consuming Events (Consumer ← Redis)
**File:** `src/consumer.py` (class `StreamConsumer`)

The consumer runs continuously on the server. Here is **exactly** what it does:

#### Step A: Create Consumer Group (once)
```
XGROUP CREATE asm:events:v1 ch_ingestors 0 MKSTREAM
```
- Creates a consumer group named `ch_ingestors`.
- `0` — Start from the beginning if the stream is new.
- `MKSTREAM` — Create the stream if it doesn't exist.
- If the group already exists, Redis returns an error; the consumer catches it and continues.

#### Step B: Read New Messages
```
XREADGROUP GROUP ch_ingestors worker-0 STREAMS asm:events:v1 > COUNT 1000 BLOCK 5000
```
- `XREADGROUP` — Read as part of a consumer group.
- `GROUP ch_ingestors worker-0` — We are "worker-0" inside the "ch_ingestors" group.
- `STREAMS asm:events:v1 >` — Read from `asm:events:v1`, and `>` means "only messages never delivered to any consumer in this group."
- `COUNT 1000` — Return up to 1,000 messages at once.
- `BLOCK 5000` — Wait up to 5 seconds if no messages are available.

**What comes back:**
```
[
  [
    "asm:events:v1",
    [
      ["1716420000000-0", {"payload": "{...json...}"}],
      ["1716420000001-0", {"payload": "{...json...}"}],
      ...
    ]
  ]
]
```

**Important:** After `XREADGROUP`, Redis marks these messages as **pending** for this consumer. They are NOT deleted yet.

#### Step C: Acknowledge Success (after ClickHouse insert)
```
XACK asm:events:v1 ch_ingestors 1716420000000-0 1716420000001-0 ...
```
- `XACK` — Tell Redis: "We successfully processed these messages."
- Redis removes them from the pending list.
- If the consumer crashes **before** `XACK`, the messages stay pending and will be reclaimed.

#### Step D: Recover Crashed Work (on startup)
```
XPENDING asm:events:v1 ch_ingestors - + 100
```
- Lists up to 100 messages stuck in the pending list.

Then, for messages idle longer than 60 seconds:
```
XCLAIM asm:events:v1 ch_ingestors worker-0 60000 <message_id> ...
```
- `XCLAIM` — Steal messages that another consumer started but never finished (probably crashed).
- `60000` — Only claim if the message has been idle for 60,000 ms (1 minute).

This is how the pipeline **survives crashes without losing data**.

---

## 4. All ClickHouse Communications (Exact Queries)

ClickHouse is the **permanent database** where all scan results live.

### 4.1 Connection
The consumer connects via **HTTP** (not TCP wire protocol) on port `8123`:
```python
httpx.AsyncClient(
    base_url="http://192.168.1.21:8123/",
    auth=("asm_ingestor", "changeme"),
)
```

### 4.2 Schema Initialization (run once)
**File:** `src/init_schema.py`

When you run `python -m src.init_schema`, these SQL statements are sent as HTTP POST bodies:

**Create database:**
```sql
CREATE DATABASE IF NOT EXISTS asm_pipeline
```

**Create events table:**
```sql
CREATE TABLE IF NOT EXISTS asm_pipeline.events (
    event_id UUID,
    event_type LowCardinality(String),
    target String,
    asset String,
    source_tool LowCardinality(String),
    scan_id UUID,
    scan_timestamp DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    data String CODEC(ZSTD(3)),
    producer_host LowCardinality(String),
    producer_version LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(scan_timestamp)
ORDER BY (event_type, target, scan_timestamp, asset)
TTL scan_timestamp + INTERVAL 12 MONTH
SETTINGS index_granularity = 8192
```

**What this means in simple terms:**
| Column | What it stores |
|--------|---------------|
| `event_id` | Unique ID for this single finding |
| `event_type` | What kind of finding: `SUBDOMAIN_FOUND`, `DNS_RESOLVED`, `PORT_FOUND`, `SERVICE_DETECTED` |
| `target` | The domain you scanned (e.g., `example.com`) |
| `asset` | The specific thing found (e.g., `www.example.com`, `93.184.216.34:443`) |
| `source_tool` | Which tool found it (`subfinder`, `dnsx`, `naabu`, `httpx`) |
| `scan_id` | UUID of the entire scan run |
| `scan_timestamp` | When the scanner produced this finding |
| `ingested_at` | When it landed in ClickHouse (auto-set) |
| `data` | All the juicy details as a JSON string (compressed with ZSTD) |
| `producer_host` | Which machine ran the scan (`laptop-001`) |
| `producer_version` | Pipeline version (`0.1.0`) |

**Table engine features:**
- `MergeTree` — ClickHouse's default high-performance table engine.
- `PARTITION BY toYYYYMM(scan_timestamp)` — Data is split into monthly folders. Querying one month is fast.
- `ORDER BY (event_type, target, scan_timestamp, asset)` — Rows are sorted on disk in this order. Makes filtering by `event_type` or `target` extremely fast.
- `TTL scan_timestamp + INTERVAL 12 MONTH` — Automatically deletes data older than 12 months.

### 4.3 Inserting Data (Consumer → ClickHouse)
**File:** `src/clickhouse_client.py` → `insert_json_each_row()`

The consumer does NOT insert one row at a time. It waits until it has a batch (default 5,000 events or every 5 seconds), then sends them all at once.

**HTTP request made:**
```
POST http://192.168.1.21:8123/?database=asm_pipeline
    &query=INSERT+INTO+events+FORMAT+JSONEachRow
    &input_format_allow_errors_num=50
    &input_format_allow_errors_ratio=0.05
```

**Request body:**
```
{"event_id":"...","event_type":"SUBDOMAIN_FOUND","target":"example.com",...}
{"event_id":"...","event_type":"DNS_RESOLVED","target":"example.com",...}
{"event_id":"...","event_type":"PORT_FOUND","target":"example.com",...}
... (5,000 lines like this)
```

**Why `JSONEachRow`?** Each line is a complete JSON object. ClickHouse parses them one by one. If one line is corrupted, the others still get inserted (thanks to `input_format_allow_errors_num`).

**What comes back:** An empty response `200 OK` means success.

**Retry logic:** If the insert fails, the consumer retries up to 3 times with exponential backoff:
- Attempt 1: immediate
- Attempt 2: wait 2 seconds
- Attempt 3: wait 4 seconds

If all retries fail, the messages are **NOT acknowledged in Redis**. They stay in the pending list and will be retried later (either by the same consumer after it recovers, or by a new consumer via `XCLAIM`).

### 4.4 Querying Data (You → ClickHouse)

**Count events by type:**
```sql
SELECT event_type, count() FROM asm_pipeline.events GROUP BY event_type
```

**See everything for a specific domain:**
```sql
SELECT * FROM asm_pipeline.events WHERE target = 'example.com' ORDER BY scan_timestamp DESC
```

**See the latest scan only:**
```sql
SELECT * FROM asm_pipeline.events
WHERE scan_id = (SELECT scan_id FROM asm_pipeline.events ORDER BY scan_timestamp DESC LIMIT 1)
```

**Find all subdomains:**
```sql
SELECT asset FROM asm_pipeline.events
WHERE target = 'example.com' AND event_type = 'SUBDOMAIN_FOUND'
```

**Find all open ports for an IP:**
```sql
SELECT data FROM asm_pipeline.events
WHERE event_type = 'PORT_FOUND' AND asset LIKE '93.184.216.34%'
```

---

## 5. The Normalizer — Turning Chaos Into Order

**File:** `src/normalizer.py`

Scanner tools output completely different formats. The normalizer converts every tool's output into the **same standard shape** (canonical event).

| Tool | Raw Output | Normalized Event Type |
|------|-----------|----------------------|
| `subfinder` | Plain text: `www.example.com` | `SUBDOMAIN_FOUND` |
| `amass` | Plain text: `www.example.com` | `SUBDOMAIN_FOUND` |
| `dnsx` | JSON: `{"host":"...","a":["..."]}` | `DNS_RESOLVED` (one per record type) |
| `naabu` | JSON: `{"ip":"...","port":443}` | `PORT_FOUND` |
| `httpx` | JSON: `{"url":"...","status_code":200,...}` | `SERVICE_DETECTED` |

Each parser:
1. Validates the raw line (skip empty/malformed lines).
2. Extracts relevant fields.
3. Creates a canonical event with `event_id`, `scan_id`, `timestamp`, etc.
4. Puts tool-specific details inside the `data` object.

---

## 6. Deduplication — Avoiding Noise

**File:** `src/normalizer.py` (functions `dedup_key` and `Deduplicator`)

If you run the same scan twice, you don't want 10,000 duplicate events. The pipeline deduplicates using a **Redis Set**.

**The dedup key is deterministic:**
- Same subdomain → same hash → stored once.
- Same DNS A record → same hash → stored once.
- Same port on same IP → same hash → stored once.

**The Set lives for 7 days** (`TTL = 604800` seconds). After that, Redis auto-deletes it, so re-scanning the same target a month later will produce new events.

---

## 7. The Consumer — The Bridge

**File:** `src/consumer.py` and `src/run_consumer.py`

The consumer is a long-running process (usually in a Docker container on the server) that does one thing forever:

```
Loop:
  1. Read batch of messages from Redis Stream (XREADGROUP)
  2. Transform each message into a flat ClickHouse row
  3. Batch-insert into ClickHouse (INSERT INTO events FORMAT JSONEachRow)
  4. If insert succeeds → ACK messages in Redis (XACK)
  5. If insert fails → DO NOT ACK → messages stay pending for retry
  6. Wait for next batch
```

**Two timers drive flushing:**
- **Size trigger:** When the buffer reaches 5,000 events → flush immediately.
- **Time trigger:** Every 5 seconds, flush whatever is in the buffer (even if only 1 event).

This balances **latency** (data appears quickly) with **throughput** (big efficient inserts).

---

## 8. Safety & Error Handling

### 8.1 Safety Limiter
**File:** `src/safety.py`

Prevents runaway scans. Every time an event is emitted, a counter increments. If it exceeds 500,000, the scan aborts with:
```
Scan exceeded safety limit of 500000 events. Aborting to prevent runaway execution.
```

### 8.2 Target Validation
**File:** `src/safety.py`

Before a scan starts, the target must:
- Not be empty.
- Contain at least one dot (basic domain check).
- (Optional) Match an allowed suffix list.

This prevents accidentally scanning `google.com` or internal IPs.

### 8.3 Tool Timeouts
**File:** `src/scanner.py`

Every subprocess has a timeout:
- `subfinder`: 10 minutes
- `amass`: 10 minutes
- `dnsx`: 2 minutes
- `naabu`: 5 minutes
- `httpx`: 3 minutes

If a tool hangs, it is killed automatically.

### 8.4 stdout Size Limit
If a tool outputs more than 512 MB of text, it is killed. Prevents memory exhaustion from broken tools.

### 8.5 Graceful Shutdown
Press `Ctrl+C` → the orchestrator finishes the current stage, then exits cleanly. The consumer also traps `SIGINT`/`SIGTERM`, does a final flush, and exits.

---

## 9. Configuration

**File:** `src/config.py` and `.env`

All settings come from environment variables with the prefix `ASM_`:

| Variable | Default | What it controls |
|----------|---------|-----------------|
| `ASM_REDIS_HOST` | `192.168.1.21` | Redis server IP |
| `ASM_REDIS_PORT` | `6379` | Redis port |
| `ASM_REDIS_PASSWORD` | `None` | Redis password |
| `ASM_CH_URL` | `http://192.168.1.21:8123/` | ClickHouse HTTP endpoint |
| `ASM_CH_USER` | `default` | ClickHouse username |
| `ASM_CH_PASSWORD` | `None` | ClickHouse password |
| `ASM_CH_DATABASE` | `asm_pipeline` | ClickHouse database name |
| `ASM_PRODUCER_HOST` | `laptop-001` | Name of the scanning machine |
| `ASM_MAX_STREAM_LEN` | `1_000_000` | Max Redis stream length |
| `ASM_BATCH_SIZE` | `5_000` | ClickHouse batch insert size |
| `ASM_FLUSH_INTERVAL` | `5.0` | Max seconds between flushes |
| `ASM_MAX_EVENTS_PER_SCAN` | `500_000` | Safety abort threshold |
| `ASM_LOG_LEVEL` | `INFO` | Logging verbosity |

---

## 10. Use Cases Explained

### Use Case 1: "I want to scan a new domain"
```bash
# Laptop
python -m src.orchestrator example.com
```
**What happens:** All 4 stages run. Events flow through Redis. Consumer inserts them into ClickHouse.

### Use Case 2: "I want to see what was found"
```sql
-- Query ClickHouse
SELECT event_type, count() FROM asm_pipeline.events WHERE target = 'example.com' GROUP BY event_type
```
**What happens:** ClickHouse scans only the partitions and index ranges relevant to `example.com`, so it's fast even with millions of rows.

### Use Case 3: "I want to export everything for one domain to a text file"
```bash
python export_domain.py example.com
```
**What happens:** The script queries ClickHouse for all rows where `target = 'example.com'`, pretty-prints the JSON `data` field, and writes to `example_com_export.txt`.

### Use Case 4: "I want to re-scan the same domain without duplicates"
```bash
python -m src.orchestrator example.com
```
**What happens:** The deduplicator recognizes hashes it saw in the last 7 days and skips them. Only **new** subdomains, ports, or services create new events.

### Use Case 5: "The consumer crashed while ingesting"
**What happens:** Messages the consumer was processing stay in the Redis pending list. When the consumer restarts, it runs `XPENDING` + `XCLAIM` to pick them up and retry.

### Use Case 6: "ClickHouse was down for 5 minutes"
**What happens:** The consumer tries to insert, fails, retries 3 times, then gives up. Messages are NOT acknowledged. They stay in Redis pending. When ClickHouse comes back online, the consumer claims them and inserts them.

### Use Case 7: "I want to wipe everything and start fresh"
```bash
# Server
docker exec asm-clickhouse clickhouse-client --query "TRUNCATE TABLE asm_pipeline.events"
docker exec asm-redis redis-cli -a changeme DEL asm:events:v1 asm:dedup:seen
```
**What happens:** The ClickHouse table is emptied. The Redis stream and dedup cache are deleted. Next scan starts from zero.

---

## 11. Data Flow Summary (One Sentence Per Step)

1. **You** run `python -m src.orchestrator example.com`.
2. **Orchestrator** validates the target and creates a `scan_id` UUID.
3. **Scanner** runs `subfinder` as a subprocess and streams stdout line-by-line.
4. **Normalizer** turns each line into a canonical `SUBDOMAIN_FOUND` event.
5. **Deduplicator** asks Redis `SADD` if this event is new.
6. **Producer** sends new events to Redis with `XADD`.
7. **Orchestrator** collects subdomains and feeds them to `dnsx`.
8. **Normalizer** turns DNS JSON into `DNS_RESOLVED` events.
9. **Deduplicator** + **Producer** filter and publish them.
10. **Orchestrator** collects IPs and feeds them to `naabu`.
11. **Normalizer** turns port JSON into `PORT_FOUND` events.
12. **Deduplicator** + **Producer** filter and publish them.
13. **Orchestrator** builds URLs and feeds them to `httpx`.
14. **Normalizer** turns HTTP JSON into `SERVICE_DETECTED` events.
15. **Deduplicator** + **Producer** filter and publish them.
16. **Consumer** (running on server) reads batches from Redis with `XREADGROUP`.
17. **Consumer** flattens events into ClickHouse rows.
18. **Consumer** sends `INSERT INTO events FORMAT JSONEachRow` to ClickHouse.
19. **If success:** Consumer runs `XACK` to remove messages from Redis.
20. **If fail:** Messages stay pending; consumer retries later.
21. **You** query ClickHouse to analyze the attack surface.

---

## 12. File Reference

| File | Role |
|------|------|
| `src/orchestrator.py` | Main scan coordinator (runs on laptop) |
| `src/scanner.py` | Runs recon tools as subprocesses |
| `src/normalizer.py` | Converts raw output to canonical events + deduplication |
| `src/producer.py` | Publishes events to Redis Stream |
| `src/consumer.py` | Reads from Redis Stream and inserts into ClickHouse |
| `src/run_consumer.py` | Entry point to start the consumer |
| `src/clickhouse_client.py` | HTTP client for ClickHouse |
| `src/init_schema.py` | One-time database/table setup |
| `src/config.py` | Loads all settings from `.env` |
| `src/safety.py` | Limits and validations |
| `export_domain.py` | Temporary script to export a domain's data to a text file |
