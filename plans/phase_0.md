# Phase 0: Security Event Ingestion Pipeline — Implementation Plan

**Version:** 1.0  
**Date:** 2026-05-21  
**Scope:** Pure pipeline engineering. No detection, no AI, no graph DB, no UI.  
**Constraint:** Laptop = compute. Remote Server (192.168.1.21) = Redis Streams + ClickHouse only.

---

## 1. SYSTEM ARCHITECTURE

### 1.1 Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              LAPTOP (Compute)                                │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │   Scanner    │───▶│  Normalizer  │───▶│ Redis Producer│                  │
│  │   Process    │    │   (Python)   │    │   Client      │                  │
│  │  (subprocess)│    │              │    │               │                  │
│  └──────────────┘    └──────────────┘    └──────┬────────┘                  │
│                                                  │                          │
│  Tools: subfinder, amass, dnsx, naabu, httpx     │ TCP/6379                 │
│                                                  ▼                          │
└──────────────────────────────────────────────────┼──────────────────────────┘
                                                   │
                              LAN (192.168.1.0/24) │
                                                   │
┌──────────────────────────────────────────────────┼──────────────────────────┐
│                         REMOTE SERVER (Storage)  │                          │
│                                                  ▼                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     Redis Streams  (port 6379)                       │   │
│  │  Stream: asm_events                                                  │   │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐  │   │
│  │  │  Producer   │    │   Stream    │    │   Consumer Group        │  │   │
│  │  │  (laptop)   │───▶│ asm_events  │───▶│  ch_ingest (on server)  │  │   │
│  │  └─────────────┘    └─────────────┘    └──────────┬────────────────┘  │   │
│  └─────────────────────────────────────────────────────┼───────────────────┘   │
│                                                        │                      │
│                                                        ▼ HTTP 8123             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     ClickHouse  (port 8123)                          │   │
│  │  Database: asm_pipeline                                              │   │
│  │  Table: events (MergeTree, partitioned by month)                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Responsibility Matrix

| Component | Location | Responsibility | Forbidden Actions |
|-----------|----------|----------------|-------------------|
| Scanners | Laptop | Execute recon tools, capture stdout/stderr | Never connect to ClickHouse directly |
| Normalizer | Laptop | Parse raw output, validate JSON schema, dedup | Never write files to server |
| Redis Producer | Laptop | XADD events to `asm_events` | No stream trimming (consumer handles) |
| Redis Server | Remote | Buffer events, manage consumer groups, PEL | No computation, no script execution |
| ClickHouse Consumer | Remote (or laptop) | XREADGROUP from Redis, batch INSERT to CH | Never scan targets |
| ClickHouse Server | Remote | Store and serve event data | No external network access |

### 1.3 Data Flow

1. **Orchestrator** (Python script on laptop) triggers scanner subprocess with timeout
2. **Scanner** writes NDJSON/CSV/line-delimited output to stdout
3. **Normalizer** parses stdout line-by-line, maps to canonical event schema
4. **Normalizer** checks deduplication cache (local Redis or in-memory)
5. **Producer** calls `XADD asm_events * event <json_blob>` for each unique event
6. **Consumer** (running on server or laptop) reads via `XREADGROUP GROUP ch_ingest worker1 ...`
7. **Consumer** accumulates N events or waits T seconds, then issues `INSERT INTO events FORMAT JSONEachRow`
8. **Consumer** XACKs successfully inserted events; failed events remain in PEL for retry

---

## 2. TOOL EXECUTION LAYER (LOCAL)

### 2.1 Execution Model

All tools run as **subprocesses** via Python `asyncio.create_subprocess_exec` with **strict timeouts** and **resource limits**. No threads for scanner I/O.

```python
import asyncio
import json
from dataclasses import dataclass
from typing import AsyncIterator, Optional

@dataclass
class RawFinding:
    tool: str
    target: str
    raw_line: str
    timestamp: str  # ISO8601 UTC

class ToolRunner:
    def __init__(self, timeout_sec: int = 600, max_stdout_mb: int = 512):
        self.timeout_sec = timeout_sec
        self.max_stdout_bytes = max_stdout_mb * 1024 * 1024

    async def run(self, cmd: list[str], target: str) -> AsyncIterator[RawFinding]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024*1024  # Stream buffer 1MB
        )
        try:
            stdout_chunks = []
            bytes_read = 0
            while True:
                line = await asyncio.wait_for(
                    proc.stdout.readline(),
                    timeout=self.timeout_sec
                )
                if not line:
                    break
                bytes_read += len(line)
                if bytes_read > self.max_stdout_bytes:
                    proc.kill()
                    raise RuntimeError(f"Stdout exceeded {self.max_stdout_mb}MB")
                yield RawFinding(
                    tool=cmd[0],
                    target=target,
                    raw_line=line.decode('utf-8', errors='replace').rstrip(),
                    timestamp=datetime.utcnow().isoformat()
                )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError(f"Tool {cmd[0]} timed out after {self.timeout_sec}s")
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            # Log stderr if non-empty and non-zero exit
            stderr = await proc.stderr.read()
            if stderr and proc.returncode != 0:
                await self._log_error(cmd[0], target, stderr.decode())
```

### 2.2 Per-Tool Specifications

#### A. Subfinder
**Purpose:** Passive subdomain discovery  
**Output format:** Line-delimited subdomains (default)  
**Recommended flags:** `-d <domain> -all -silent -o -`  
**Parsing strategy:** Each non-empty line is a subdomain

```python
async def run_subfinder(domain: str) -> AsyncIterator[RawFinding]:
    cmd = [
        "subfinder", "-d", domain,
        "-all",      # Use all sources
        "-silent",   # No banner
        "-o", "-"    # Output to stdout
    ]
    async for finding in tool_runner.run(cmd, domain):
        # raw_line = "subdomain.example.com"
        yield finding
```

**Failure modes:**
- API keys exhausted for passive sources → partial results, stderr contains "rate limit"
- Zero subdomains found → valid empty result, not a failure
- Non-zero exit code → log stderr, discard output (sources may be corrupted)

**Timeout:** 300s (passive sources are fast)

#### B. Amass
**Purpose:** Active + passive subdomain enumeration (deeper but slower)  
**Output format:** Line-delimited subdomains with `-passive` or JSON with `-json`  
**Recommended flags:** `enum -d <domain> -passive -silent -o -`  
**Parsing strategy:** Same as subfinder; one subdomain per line

```python
async def run_amass(domain: str) -> AsyncIterator[RawFinding]:
    cmd = [
        "amass", "enum",
        "-d", domain,
        "-passive",  # Avoid DNS resolution to stay polite
        "-silent",
        "-o", "-"
    ]
    async for finding in tool_runner.run(cmd, domain):
        yield finding
```

**Failure modes:**
- Config file missing → stderr warning; usually non-fatal
- Memory exhaustion (amass is heavy) → enforce 4GB process limit via `ulimit` wrapper
- Hanging on network I/O → strict 600s timeout, then SIGKILL

**Timeout:** 600s

#### C. dnsx
**Purpose:** DNS resolution and record enumeration  
**Output format:** JSON lines (`-json`) or CSV  
**Recommended flags:** `-l <subdomains_file> -a -aaaa -cname -resp -json -o -`  
**Parsing strategy:** Parse JSON per line

```python
async def run_dnsx(subdomains: list[str]) -> AsyncIterator[RawFinding]:
    # Write subdomains to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('\n'.join(subdomains))
        input_file = f.name

    cmd = [
        "dnsx", "-l", input_file,
        "-a", "-aaaa", "-cname",
        "-resp",       # Include DNS response
        "-json",
        "-o", "-"
    ]
    async for finding in tool_runner.run(cmd, input_file):
        # raw_line = '{"host":"sub.example.com","a":["1.2.3.4"],...}'
        yield finding
```

**Failure modes:**
- DNS resolver failure → empty output; retry with different resolver (`-r 8.8.8.8`)
- Massive input list → split into batches of 10,000 to avoid memory issues
- NXDOMAIN flood → valid negative results, do not treat as error

**Timeout:** 120s per batch of 10k

#### D. Naabu
**Purpose:** Port scanning  
**Output format:** Host:Port lines (default) or CSV/JSON  
**Recommended flags:** `-host <host> -p - -silent -json -o -`  
**Parsing strategy:** JSON lines preferred

```python
async def run_naabu(hosts: list[str]) -> AsyncIterator[RawFinding]:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('\n'.join(hosts))
        input_file = f.name

    cmd = [
        "naabu", "-list", input_file,
        "-p", "-",      # Top 1000 ports (use explicit list for control)
        "-silent",
        "-json",
        "-o", "-",
        "-rate", "1000"  # Packets per second limit
    ]
    async for finding in tool_runner.run(cmd, ','.join(hosts[:5])):
        # raw_line = '{"ip":"1.2.3.4","port":443,...}'
        yield finding
```

**Failure modes:**
- Requires root/sudo for SYN scans → fallback to CONNECT scan (`-scan-type c`)
- Host unreachable → empty output, valid
- Rate limiting by upstream firewall → reduce `-rate`, retry once

**Timeout:** 300s per batch

#### E. httpx
**Purpose:** HTTP probing, tech detection, response capture  
**Output format:** JSON lines (`-json`)  
**Recommended flags:** `-l <urls_file> -silent -json -o - -tech-detect -title -status-code`  
**Parsing strategy:** JSON lines

```python
async def run_httpx(urls: list[str]) -> AsyncIterator[RawFinding]:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write('\n'.join(urls))
        input_file = f.name

    cmd = [
        "httpx", "-l", input_file,
        "-silent",
        "-json",
        "-o", "-",
        "-tech-detect",
        "-title",
        "-status-code",
        "-threads", "50"
    ]
    async for finding in tool_runner.run(cmd, input_file):
        yield finding
```

**Failure modes:**
- Connection timeouts → normal for dead hosts
- SSL errors → captured in JSON output as `"error":"ssl_error"`; still valid event
- Massive URL list → chunked into batches of 5,000

**Timeout:** 180s per batch

### 2.3 Subprocess Resource Limits

Wrap all scanner commands with `prlimit` (Linux) or enforce via Python `resource` module on Unix:

```python
import resource

def set_limits():
    # 4GB memory max per scanner
    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 * 1024 * 1024, -1))
    # 30 max open files (prevents FD exhaustion)
    resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))

# Apply before subprocess execution via preexec_fn
```

On Windows (laptop may be Windows), use `joblib` or Windows Job Objects to enforce memory limits, or rely on the `max_stdout_bytes` read limit as primary protection.

### 2.4 Error Classification

| Severity | Condition | Action |
|----------|-----------|--------|
| Fatal | Tool not installed | Log CRITICAL, halt pipeline |
| Fatal | Process OOM killed | Log ERROR, do not retry (reduce scope) |
| Retryable | Timeout | Log WARN, retry once with 2x timeout |
| Retryable | DNS/Network unreachable | Log WARN, retry once after 5s |
| Ignorable | Non-zero exit with valid stdout | Parse stdout, log stderr as WARN |
| Ignorable | Empty output | Valid result, emit zero events |

---

## 3. EVENT NORMALIZATION LAYER (LOCAL)

### 3.1 Canonical Event Schema (Strict JSON)

Every event emitted to Redis MUST conform to this schema. No extra fields allowed without migration.

```json
{
  "event_id": "uuidv4",
  "event_type": "SUBDOMAIN_FOUND | DNS_RESOLVED | PORT_FOUND | SERVICE_DETECTED",
  "target": "example.com",
  "asset": "sub.example.com | 1.2.3.4 | sub.example.com:443",
  "source_tool": "subfinder | amass | dnsx | naabu | httpx",
  "scan_id": "uuidv4",
  "scan_timestamp": "2026-05-21T12:00:00Z",
  "data": { ... },
  "metadata": {
    "producer_host": "laptop-001",
    "producer_version": "0.1.0"
  }
}
```

#### Event Type: SUBDOMAIN_FOUND

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "event_type": "SUBDOMAIN_FOUND",
  "target": "example.com",
  "asset": "api.example.com",
  "source_tool": "subfinder",
  "scan_id": "660e8400-e29b-41d4-a716-446655440001",
  "scan_timestamp": "2026-05-21T12:00:00Z",
  "data": {
    "subdomain": "api.example.com",
    "source": "crtsh",           // where subfinder found it
    "is_wildcard": false
  },
  "metadata": {
    "producer_host": "laptop-001",
    "producer_version": "0.1.0"
  }
}
```

#### Event Type: DNS_RESOLVED

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440001",
  "event_type": "DNS_RESOLVED",
  "target": "example.com",
  "asset": "api.example.com",
  "source_tool": "dnsx",
  "scan_id": "660e8400-e29b-41d4-a716-446655440001",
  "scan_timestamp": "2026-05-21T12:05:00Z",
  "data": {
    "hostname": "api.example.com",
    "record_type": "A",
    "resolved_values": ["1.2.3.4", "1.2.3.5"],
    "resolver_used": "8.8.8.8",
    "response_time_ms": 45
  },
  "metadata": { ... }
}
```

#### Event Type: PORT_FOUND

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440002",
  "event_type": "PORT_FOUND",
  "target": "example.com",
  "asset": "1.2.3.4:443",
  "source_tool": "naabu",
  "scan_id": "660e8400-e29b-41d4-a716-446655440001",
  "scan_timestamp": "2026-05-21T12:10:00Z",
  "data": {
    "ip": "1.2.3.4",
    "port": 443,
    "protocol": "tcp",
    "scan_type": "syn"
  },
  "metadata": { ... }
}
```

#### Event Type: SERVICE_DETECTED

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440003",
  "event_type": "SERVICE_DETECTED",
  "target": "example.com",
  "asset": "https://api.example.com:443",
  "source_tool": "httpx",
  "scan_id": "660e8400-e29b-41d4-a716-446655440001",
  "scan_timestamp": "2026-05-21T12:15:00Z",
  "data": {
    "url": "https://api.example.com",
    "host": "api.example.com",
    "ip": "1.2.3.4",
    "port": 443,
    "scheme": "https",
    "status_code": 200,
    "title": "API Gateway",
    "technologies": ["nginx", "Express", "React"],
    "headers": {
      "server": "nginx/1.18.0",
      "x-powered-by": "Express"
    },
    "tls_version": "TLSv1.3",
    "response_hash_sha256": "abc123..."
  },
  "metadata": { ... }
}
```

### 3.2 Transformation Logic (Pseudocode → Python)

```python
import uuid
import json
from datetime import datetime, timezone

class EventNormalizer:
    def __init__(self, scan_id: str, producer_host: str):
        self.scan_id = scan_id
        self.producer_host = producer_host
        self.base_meta = {
            "producer_host": producer_host,
            "producer_version": "0.1.0"
        }

    def normalize(self, raw: RawFinding) -> Optional[dict]:
        parsers = {
            "subfinder": self._parse_subfinder,
            "amass": self._parse_amass,
            "dnsx": self._parse_dnsx,
            "naabu": self._parse_naabu,
            "httpx": self._parse_httpx
        }
        parser = parsers.get(raw.tool)
        if not parser:
            return None
        return parser(raw)

    def _parse_subfinder(self, raw: RawFinding) -> dict:
        subdomain = raw.raw_line.strip()
        if not subdomain or '.' not in subdomain:
            return None
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "SUBDOMAIN_FOUND",
            "target": raw.target,
            "asset": subdomain,
            "source_tool": "subfinder",
            "scan_id": self.scan_id,
            "scan_timestamp": raw.timestamp,
            "data": {
                "subdomain": subdomain,
                "source": "passive",
                "is_wildcard": subdomain.startswith("*.")
            },
            "metadata": self.base_meta.copy()
        }

    def _parse_dnsx(self, raw: RawFinding) -> list[dict]:
        try:
            j = json.loads(raw.raw_line)
        except json.JSONDecodeError:
            return []

        events = []
        host = j.get("host", "")
        base = {
            "event_id": str(uuid.uuid4()),
            "event_type": "DNS_RESOLVED",
            "target": raw.target,
            "asset": host,
            "source_tool": "dnsx",
            "scan_id": self.scan_id,
            "scan_timestamp": raw.timestamp,
            "metadata": self.base_meta.copy()
        }

        for rtype in ["a", "aaaa", "cname"]:
            values = j.get(rtype)
            if values:
                ev = base.copy()
                ev["event_id"] = str(uuid.uuid4())
                ev["data"] = {
                    "hostname": host,
                    "record_type": rtype.upper(),
                    "resolved_values": values if isinstance(values, list) else [values],
                    "resolver_used": j.get("resolver", ""),
                    "response_time_ms": j.get("response_time_ms", 0)
                }
                events.append(ev)
        return events

    def _parse_naabu(self, raw: RawFinding) -> Optional[dict]:
        try:
            j = json.loads(raw.raw_line)
        except json.JSONDecodeError:
            return None
        ip = j.get("ip", j.get("host", ""))
        port = j.get("port", 0)
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "PORT_FOUND",
            "target": raw.target,
            "asset": f"{ip}:{port}",
            "source_tool": "naabu",
            "scan_id": self.scan_id,
            "scan_timestamp": raw.timestamp,
            "data": {
                "ip": ip,
                "port": port,
                "protocol": j.get("protocol", "tcp"),
                "scan_type": j.get("scan_type", "connect")
            },
            "metadata": self.base_meta.copy()
        }

    def _parse_httpx(self, raw: RawFinding) -> Optional[dict]:
        try:
            j = json.loads(raw.raw_line)
        except json.JSONDecodeError:
            return None
        url = j.get("url", "")
        host = j.get("host", "")
        ip = j.get("ip", "")
        port = j.get("port", 0)
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "SERVICE_DETECTED",
            "target": raw.target,
            "asset": url or f"{host}:{port}",
            "source_tool": "httpx",
            "scan_id": self.scan_id,
            "scan_timestamp": raw.timestamp,
            "data": {
                "url": url,
                "host": host,
                "ip": ip,
                "port": port,
                "scheme": j.get("scheme", "https"),
                "status_code": j.get("status_code", 0),
                "title": j.get("title", ""),
                "technologies": j.get("tech", []),
                "headers": {k.lower(): v for k, v in (j.get("headers", {}) or {}).items()},
                "tls_version": j.get("tls_version", ""),
                "response_hash_sha256": j.get("body_sha256", "")
            },
            "metadata": self.base_meta.copy()
        }

    def _parse_amass(self, raw: RawFinding) -> dict:
        # Same as subfinder; one subdomain per line
        return self._parse_subfinder(raw)
```

### 3.3 Deduplication Strategy

**Goal:** Prevent duplicate events across scans without querying ClickHouse (too slow).

**Approach:** Local probabilistic deduplication using Redis `SET` with TTL.

**Deduplication Key:** Deterministic hash of (`event_type`, `asset`, normalized `data` subset)

```python
import hashlib

def dedup_key(event: dict) -> str:
    """Generate deterministic key for deduplication."""
    if event["event_type"] == "SUBDOMAIN_FOUND":
        raw = f"sub:{event['asset']}"
    elif event["event_type"] == "DNS_RESOLVED":
        vals = ','.join(sorted(event["data"]["resolved_values"]))
        raw = f"dns:{event['data']['hostname']}:{event['data']['record_type']}:{vals}"
    elif event["event_type"] == "PORT_FOUND":
        raw = f"port:{event['data']['ip']}:{event['data']['port']}:{event['data']['protocol']}"
    elif event["event_type"] == "SERVICE_DETECTED":
        raw = f"svc:{event['asset']}:{event['data']['status_code']}"
    else:
        raw = json.dumps(event, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()
```

**Redis dedup implementation:**

```python
class Deduplicator:
    def __init__(self, redis_client, ttl_sec: int = 86400 * 7):
        self.r = redis_client
        self.ttl = ttl_sec
        self.set_key = "asm:dedup:seen"

    async def is_duplicate(self, event: dict) -> bool:
        key = dedup_key(event)
        # SADD returns 0 if member already exists
        added = await self.r.sadd(self.set_key, key)
        if added:
            await self.r.expire(self.set_key, self.ttl)
            return False
        return True
```

**Rationale:**
- Uses Redis `SET` on the remote server (shared across laptop restarts)
- 7-day TTL prevents unbounded growth
- SHA256 keys are 64 bytes each; 1M events = ~64MB + overhead
- If Redis is unreachable, **fail open** (allow duplicates) rather than blocking pipeline

**Edge case:** If ClickHouse is down for >7 days and Redis TTL expires, duplicates re-enter. Acceptable for Phase 0.

---

## 4. REDIS STREAMS DESIGN (REMOTE BUFFER LAYER)

### 4.1 Stream Configuration

| Property | Value |
|----------|-------|
| Stream Key | `asm:events:v1` |
| Producer | Laptop Python client (async redis-py) |
| Consumer Group | `ch_ingestors` |
| Consumers | `worker-0`, `worker-1`, ... (1 is fine for Phase 0) |
| Message ID | Auto-generated by Redis (`*`)

### 4.2 Message Format inside Stream

Redis Streams are key-value maps. Each entry:

```
XADD asm:events:v1 * payload <json_string>
```

**Why single `payload` field instead of flattening JSON?**
- ClickHouse `JSONEachRow` ingestion expects complete JSON objects
- Flattening into Redis fields requires re-serialization anyway
- Single payload field keeps stream entries uniform

**Maxlen Policy (Backpressure):**

```
XADD asm:events:v1 MAXLEN ~ 1000000 * payload <json>
```

- `MAXLEN ~ 1000000`: Approximate trim to 1M entries (~1GB if events are 1KB)
- Approximate (`~`) is fast; exact trim blocks producer
- If consumer is down for extended period, old events are lost. **This is by design** — buffer, not archive.

### 4.3 Producer Implementation (Laptop)

```python
import redis.asyncio as redis
import json

class RedisEventProducer:
    def __init__(self, host: str = "192.168.1.21", port: int = 6379,
                 password: str = None, db: int = 0,
                 max_stream_len: int = 1_000_000):
        self.redis = redis.Redis(
            host=host, port=port, password=password, db=db,
            socket_connect_timeout=10,
            socket_keepalive=True,
            health_check_interval=30
        )
        self.stream_key = "asm:events:v1"
        self.max_stream_len = max_stream_len

    async def publish(self, event: dict) -> str:
        payload = json.dumps(event, separators=(',', ':'))
        msg_id = await self.redis.xadd(
            self.stream_key,
            {"payload": payload},
            maxlen=self.max_stream_len,
            approximate=True
        )
        return msg_id.decode() if isinstance(msg_id, bytes) else msg_id

    async def publish_batch(self, events: list[dict]) -> list[str]:
        pipe = self.redis.pipeline()
        for event in events:
            payload = json.dumps(event, separators=(',', ':'))
            pipe.xadd(self.stream_key, {"payload": payload},
                      maxlen=self.max_stream_len, approximate=True)
        return await pipe.execute()
```

### 4.4 Consumer Group Design (Server-Side or Laptop)

**Where does the consumer run?**
- Phase 0: Consumer runs on **laptop** (simpler deployment) OR on server via Docker
- Recommended: Consumer is a Docker container on the **remote server** reading from local Redis and writing to local ClickHouse. This removes network hops for ingestion.

```python
class StreamConsumer:
    def __init__(self, redis_client, consumer_group: str, consumer_name: str,
                 batch_size: int = 1000, block_ms: int = 5000):
        self.r = redis_client
        self.group = consumer_group
        self.name = consumer_name
        self.stream_key = "asm:events:v1"
        self.batch_size = batch_size
        self.block_ms = block_ms
        self._ensure_group()

    def _ensure_group(self):
        try:
            self.r.xgroup_create(self.stream_key, self.group, id="0", mkstream=True)
        except redis.ResponseError as e:
            if "already exists" not in str(e):
                raise

    async def read_batch(self) -> list[tuple]:
        """Returns list of (msg_id, payload_dict)"""
        resp = await self.r.xreadgroup(
            groupname=self.group,
            consumername=self.name,
            streams={self.stream_key: ">"},
            count=self.batch_size,
            block=self.block_ms
        )
        results = []
        if resp:
            for stream_name, entries in resp:
                for msg_id, fields in entries:
                    payload = fields.get(b"payload") or fields.get("payload")
                    if payload:
                        try:
                            data = json.loads(payload)
                            results.append((msg_id, data))
                        except json.JSONDecodeError:
                            # Bad message: ACK it to dead-letter
                            await self.r.xack(self.stream_key, self.group, msg_id)
        return results

    async def ack(self, msg_ids: list):
        if msg_ids:
            await self.r.xack(self.stream_key, self.group, *msg_ids)
```

### 4.5 ACK Mechanism & Retry Strategy

**Two-phase commit pattern:**
1. XREADGROUP → events claimed by consumer (added to PEL)
2. Insert into ClickHouse
3. XACK on success
4. On failure: leave in PEL. Redis tracks delivery count via XPENDING.

**Retry via Pending Entries List (PEL):**

```python
async def recover_pending(self, idle_min_ms: int = 60000):
    """Claim messages idle for >60s (previous consumer crashed)."""
    pending = await self.r.xpending_range(
        self.stream_key, self.group,
        min="-", max="+", count=100
    )
    for item in pending:
        if item["time_since_delivered"] > idle_min_ms:
            claimed = await self.r.xclaim(
                self.stream_key, self.group,
                self.name, min_idle_time=idle_min_ms,
                message_ids=[item["message_id"]]
            )
            # Process claimed messages
```

**Max retry:** If a message fails insertion 3 times, XACK it and write to `asm:events:v1:deadletter` stream for manual inspection.

### 4.6 Backpressure Handling

| Scenario | Behavior |
|----------|----------|
| Consumer healthy but slow | Redis stream grows. `MAXLEN ~ 1M` trims old events. Acceptable loss. |
| Consumer down | Stream grows to maxlen, then producers drop old events. Monitor via `XLEN`. |
| Producer faster than consumer | Increase batch_size (Redis read) and ClickHouse batch insert size. Add consumers (parallelism limited by ClickHouse). |
| Network partition laptop→Redis | Producer blocks on XADD with timeout. Buffer in local SQLite if critical (see Fallback). |

**Monitoring command:**
```
XLEN asm:events:v1
XPENDING asm:events:v1 ch_ingestors
```

---

## 5. CLICKHOUSE INTEGRATION (REMOTE STORAGE LAYER)

### 5.1 Connection Model

**Interface:** HTTP on port 8123  
**Driver:** `requests` (sync) or `httpx` (async) — no heavy native driver needed for Phase 0  
**URL:** `http://192.168.1.21:8123`

```python
import httpx

class ClickHouseClient:
    def __init__(self, url: str = "http://192.168.1.21:8123",
                 database: str = "asm_pipeline",
                 username: str = "default",
                 password: str = ""):
        self.url = url
        self.database = database
        self.auth = (username, password) if password else None
        self.session = httpx.AsyncClient(timeout=30.0)

    async def execute(self, query: str) -> str:
        params = {"database": self.database, "query": query}
        resp = await self.session.post(self.url, params=params, auth=self.auth)
        resp.raise_for_status()
        return resp.text

    async def insert_json_each_row(self, table: str, rows: list[dict]):
        """Batch insert via JSONEachRow format."""
        body = '\n'.join(json.dumps(r, separators=(',', ':')) for r in rows)
        params = {
            "database": self.database,
            "query": f"INSERT INTO {table} FORMAT JSONEachRow",
            "input_format_allow_errors_num": 10,
            "input_format_allow_errors_ratio": 0.05
        }
        resp = await self.session.post(
            self.url, params=params, content=body, auth=self.auth
        )
        resp.raise_for_status()
        return resp.text
```

### 5.2 Schema Design

**Database:** `asm_pipeline`

**Table:** `events`

```sql
CREATE DATABASE IF NOT EXISTS asm_pipeline;

CREATE TABLE IF NOT EXISTS asm_pipeline.events (
    -- Identity & Classification
    event_id UUID,
    event_type LowCardinality(String),
    target String,
    asset String,
    source_tool LowCardinality(String),
    scan_id UUID,
    
    -- Timing
    scan_timestamp DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    
    -- Hierarchical materialized columns for fast filtering
    target_domain String MATERIALIZED target,
    asset_host String MATERIALIZED if(event_type = 'DNS_RESOLVED', asset, '')
    
    -- Raw payload (schema on read)
    data String CODEC(ZSTD(3)),
    
    -- Producer metadata
    producer_host LowCardinality(String),
    producer_version LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(scan_timestamp)
ORDER BY (event_type, target, scan_timestamp, asset)
TTL scan_timestamp + INTERVAL 12 MONTH  -- Auto-delete after 1 year
SETTINGS index_granularity = 8192;
```

**Schema Justification:**
- `LowCardinality(String)`: Massive compression for enum-like fields (event_type, tool)
- `PARTITION BY toYYYYMM`: Drop old months instantly, optimize time-range queries
- `ORDER BY (event_type, target, scan_timestamp, asset)`: Primary use case is "show me all DNS_RESOLVED events for example.com in last 7 days"
- `data String`: Stores full JSON payload as raw string. ClickHouse is schema-on-read friendly; we avoid 50 nested columns that change every scanner version.
- `CODEC(ZSTD(3))`: Aggressive compression for JSON payloads (typically 3-5x)
- `TTL`: Prevents unbounded disk growth. 12 months is enough for trend analysis.

**Projection for fast asset lookups (optional Phase 0.5):**
```sql
ALTER TABLE asm_pipeline.events
ADD PROJECTION asset_lookup
(
    SELECT * ORDER BY asset, scan_timestamp
);
```

### 5.3 Ingestion Strategy

**Batching is non-negotiable.** ClickHouse INSERT performance degrades catastrophically with row-by-row inserts.

**Consumer batch loop (server-side):**

```python
class ClickHouseIngester:
    def __init__(self, redis_consumer: StreamConsumer, ch_client: ClickHouseClient,
                 batch_size: int = 5000, flush_interval_sec: float = 5.0,
                 max_retries: int = 3):
        self.consumer = redis_consumer
        self.ch = ch_client
        self.batch_size = batch_size
        self.flush_interval = flush_interval_sec
        self.max_retries = max_retries
        self._buffer = []
        self._pending_ids = []

    async def run(self):
        last_flush = time.time()
        while True:
            # Read from Redis (blocks up to 5s)
            messages = await self.consumer.read_batch()
            
            for msg_id, event in messages:
                # Flatten for ClickHouse
                row = {
                    "event_id": event["event_id"],
                    "event_type": event["event_type"],
                    "target": event["target"],
                    "asset": event["asset"],
                    "source_tool": event["source_tool"],
                    "scan_id": event["scan_id"],
                    "scan_timestamp": event["scan_timestamp"],
                    "data": json.dumps(event["data"]),
                    "producer_host": event["metadata"]["producer_host"],
                    "producer_version": event["metadata"]["producer_version"]
                }
                self._buffer.append(row)
                self._pending_ids.append(msg_id)

            # Flush conditions
            now = time.time()
            if len(self._buffer) >= self.batch_size or (now - last_flush) >= self.flush_interval:
                await self._flush()
                last_flush = now

    async def _flush(self):
        if not self._buffer:
            return

        for attempt in range(self.max_retries):
            try:
                await self.ch.insert_json_each_row("events", self._buffer)
                await self.consumer.ack(self._pending_ids)
                self._buffer.clear()
                self._pending_ids.clear()
                return
            except Exception as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    # Max retries exceeded: leave in PEL for another worker
                    # Or requeue to deadletter stream
                    await self._deadletter(self._buffer, str(e))
                    # ACK to prevent infinite retry loop
                    await self.consumer.ack(self._pending_ids)
                    self._buffer.clear()
                    self._pending_ids.clear()

    async def _deadletter(self, rows: list[dict], error: str):
        # Write to separate stream or local file
        pass
```

**Batch sizing rationale:**
- 5,000 rows × 1KB = 5MB per INSERT
- ClickHouse handles 5MB inserts comfortably on modest hardware
- At 50K events/scan, this is 10 INSERTs
- If latency matters, reduce to 1,000 rows / 1 second

### 5.4 Fallback Strategy (ClickHouse Down)

If ClickHouse is unreachable:
1. Consumer catches `httpx.ConnectError`
2. Backoff retry 3 times over 30 seconds
3. If still down: **pause consumption** (do not XACK)
4. Redis stream accumulates (up to MAXLEN limit)
5. Alert via logging: `CRITICAL: ClickHouse ingestion stalled, Redis backlog growing`
6. If laptop must continue: write batches to local SQLite/Parquet as emergency spillover

```python
class EmergencySpillover:
    def __init__(self, db_path: str = "/tmp/asm_spillover.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("CREATE TABLE IF NOT EXISTS events (payload TEXT)")

    async def write(self, rows: list[dict]):
        self.conn.executemany(
            "INSERT INTO events VALUES (?)",
            [(json.dumps(r),) for r in rows]
        )
        self.conn.commit()
```

**Recovery:** When ClickHouse returns, a separate backfill script reads SQLite and INSERTs into ClickHouse, then deletes local rows.

---

## 6. FAILURE HANDLING MODEL

### 6.1 Failure Scenario Matrix

| Scenario | Detection | Response | Data Loss? |
|----------|-----------|----------|------------|
| **Laptop process crash mid-scan** | Scanner subprocess exits; parent Python exception | Orchestrator catches SIGTERM/SIGINT, flushes current Redis batch, exits gracefully. If hard crash (SIGKILL), events in local buffer lost. Events already XADD'd are safe in Redis. | Partial: unflushed local buffer |
| **Redis unreachable** | `redis.ConnectionError` on XADD | Producer retries 3× with exponential backoff. If persistent: spill to local SQLite buffer. Resume XADD when Redis returns. | No (spillover) |
| **ClickHouse downtime** | `httpx.ConnectError` on INSERT | Consumer stops ACKing. Redis backlog grows. If >MAXLEN, old events dropped. Alert emitted. | Yes, if outage exceeds buffer capacity |
| **Network instability (packet loss)** | TCP timeouts | Redis client auto-reconnects with `socket_keepalive=True`. HTTP retries with backoff. | No |
| **Partial scan results** | Tool exits non-zero after emitting partial stdout | Normalizer processes valid stdout lines. Stderr logged. Event count vs expected logged as WARN. | No (partial is better than nothing) |
| **Duplicate event injection** | Dedup check via Redis SET | Duplicate filtered before XADD. If Redis down, dedup fails open → duplicates reach ClickHouse. | No harm, just noise |
| **Corrupted JSON in stream** | `json.JSONDecodeError` in consumer | Consumer XACKs immediately (prevent PEL poisoning), writes to `asm:events:v1:deadletter`. | Message isolated |
| **Consumer crash during flush** | Buffer in memory, IDs in `_pending_ids` | Messages remain in PEL. Idle for 60s, claimed by new consumer instance via `XAUTOCLAIM` or `XCLAIM`. | No |

### 6.2 Graceful Shutdown Protocol

```python
import signal

class PipelineOrchestrator:
    def __init__(self):
        self.shutdown_event = asyncio.Event()
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        self.shutdown_event.set()

    async def run(self):
        # ... start producers and consumer ...
        await self.shutdown_event.wait()
        # 1. Stop launching new scanner processes
        # 2. Wait for running scanners to complete (with timeout)
        # 3. Flush local event buffer to Redis (best effort)
        # 4. Close Redis connection
        # 5. If consumer runs locally: flush CH buffer, exit
```

### 6.3 Checkpointing

Since Redis Streams are persistent (if `appendonly yes` in Redis config), the stream itself is the checkpoint. Consumers restart from last acknowledged position automatically via consumer group.

**Redis persistence requirement:**
```
# redis.conf on remote server
appendonly yes
appendfsync everysec
```

---

## 7. SCALABILITY MODEL (REALISTIC LIMITS)

### 7.1 Bottleneck Analysis

| Component | Theoretical Limit | Realistic Limit (Phase 0) | Bottleneck |
|-----------|-------------------|---------------------------|------------|
| **Laptop CPU** | 8-16 cores | 4 concurrent scanners | Context switching, thermal throttling on sustained load |
| **Network (Laptop → Redis)** | 1 Gbps LAN | ~100 MB/s | Not a bottleneck for text events |
| **Network (Redis → ClickHouse)** | Localhost if co-located | ~50 MB/s | HTTP overhead, JSON parsing |
| **Redis Streams** | 1M+ ops/sec | 10K XADD/sec | Memory for stream backlog |
| **ClickHouse Inserts** | 2M rows/sec (optimal) | 50K-200K rows/sec | JSONEachRow parsing, small batches |

**Phase 0 realistic throughput:** 1,000 events/second sustained, 10,000 events/second burst (during flush).

### 7.2 Resource Math

**Event sizes:**
- SUBDOMAIN_FOUND: ~300 bytes JSON
- DNS_RESOLVED: ~500 bytes JSON
- PORT_FOUND: ~400 bytes JSON
- SERVICE_DETECTED: ~2-5 KB JSON (headers, tech lists)
- Average: ~800 bytes

**Redis memory:**
- 1M events in stream × 800 bytes × 2 (Redis overhead) = **1.6 GB**
- Dedup SET: 1M entries × 64 bytes = **64 MB**
- Total: **~2 GB** for 1M event buffer

**ClickHouse storage:**
- 1M events × 800 bytes × 0.3 (ZSTD compression) = **240 MB per month**
- 12 months TTL = **~3 GB**

### 7.3 Mitigation Strategies

| Bottleneck | Mitigation |
|------------|------------|
| Laptop CPU saturated | Limit concurrent tools to 2. Run amass/subfinder sequentially. Network I/O bound tools (naabu, httpx) parallelize better. |
| Redis memory growth | `MAXLEN ~ 1000000` enforced. Monitor with `INFO memory`. If server has <4GB RAM, reduce to 500K. |
| ClickHouse insert too slow | Increase batch size to 20,000. Use `async_insert` setting in ClickHouse. Switch to `Native` format if JSONEachRow is CPU-bound. |
| Network partition | Local spillover SQLite. Backfill when connectivity returns. |
| Too many events from amass | Amass can emit 100K+ subdomains for large scopes. Pre-filter: ignore wildcard matches, dedup before XADD. |

### 7.4 Concurrency Model

```
Laptop:
  ├─ Scanner Pool: max 3 concurrent subprocesses
  ├─ Normalizer: asyncio task per scanner stream (5 tasks)
  ├─ Dedup: async Redis SADD calls (non-blocking)
  └─ Producer: async Redis XADD calls (non-blocking)

Server:
  └─ Consumer: 1-2 workers (more workers = more parallel CH inserts, but CH prefers fewer large inserts)
```

**Do not** run 10 scanner processes. Laptop thermal throttling and network congestion will degrade performance. Run 2-3 scanners in pipeline stages:
1. Stage 1: subfinder + amass (subdomains) → dnsx
2. Stage 2: dnsx results → naabu
3. Stage 3: naabu results → httpx

---

## 8. SECURITY MODEL

### 8.1 Network Security

**Assumption:** 192.168.1.0/24 is a trusted LAN. No public internet exposure.

**Redis:**
```
# redis.conf
bind 192.168.1.21 127.0.0.1
protected-mode yes
requirepass <strong_password>
```

Producer connects with password. If Redis port is accidentally exposed to WAN, password prevents trivial access.

**ClickHouse:**
```xml
<!-- users.xml -->
<asm_pipeline>
    <password_sha256_hex>...</password_sha256_hex>
    <networks>
        <ip>192.168.1.0/24</ip>
        <ip>127.0.0.1/32</ip>
    </networks>
    <profile>readonly_plus_insert</profile>
</asm_pipeline>
```
- Create dedicated user `asm_ingestor` with INSERT-only permissions on `asm_pipeline.events`
- Disable default user or restrict to localhost

### 8.2 Credential Handling

**Never** commit credentials to git.

```python
# config.py loads from environment
import os

REDIS_HOST = os.getenv("ASM_REDIS_HOST", "192.168.1.21")
REDIS_PORT = int(os.getenv("ASM_REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("ASM_REDIS_PASSWORD")  # Required, no default
CH_URL = os.getenv("ASM_CH_URL", "http://192.168.1.21:8123")
CH_PASSWORD = os.getenv("ASM_CH_PASSWORD")  # Required
```

**`.env` file (gitignored):**
```
ASM_REDIS_PASSWORD=REPLACE_ME_STRONG_PASSWORD
ASM_CH_PASSWORD=REPLACE_ME_STRONG_PASSWORD
```

### 8.3 Rate Limiting & Scan Safety

**Per-target rate limits:**
- Subfinder/Amass: Passive sources already rate-limited. No additional throttle needed.
- dnsx: Max 1000 queries/second to avoid resolver blacklisting.
- naabu: Max 1000 packets/second (`-rate 1000`).
- httpx: Max 50 threads (`-threads 50`).

**Global safety valve:**
```python
class SafetyLimiter:
    def __init__(self, max_events_per_scan: int = 500_000):
        self.max_events = max_events_per_scan
        self.count = 0

    def check(self) -> bool:
        self.count += 1
        if self.count > self.max_events:
            raise RuntimeError(f"Scan exceeded {self.max_events} events. Aborting to prevent runaway.")
        return True
```

**Scope validation:**
```python
def validate_target(target: str) -> bool:
    """Ensure target is in authorized scope."""
    allowed_suffixes = [".example.com", "-example.com"]
    return any(target.endswith(s) or s in target for s in allowed_suffixes)
```

### 8.4 Data Retention & Privacy

- ClickHouse TTL: 12 months automatic deletion
- Redis MAXLEN: ~1M events (hours to days of buffer)
- No PII expected in ASM data, but if discovered (emails in CT logs), it is metadata from public sources
- Run scanners from infrastructure you own or have written authorization to test

---

## 9. IMPLEMENTATION CHECKLIST

### 9.1 Remote Server Setup (192.168.1.21)

```bash
# docker-compose.yml on remote server
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    ports:
      - "192.168.1.21:6379:6379"
    volumes:
      - ./redis.conf:/usr/local/etc/redis/redis.conf
      - redis_data:/data
    command: redis-server /usr/local/etc/redis/redis.conf

  clickhouse:
    image: clickhouse/clickhouse-server:latest
    ports:
      - "192.168.1.21:8123:8123"
      - "192.168.1.21:9000:9000"
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - ./clickhouse-config.xml:/etc/clickhouse-server/config.d/custom.xml
      - ./users.xml:/etc/clickhouse-server/users.d/asm.xml

volumes:
  redis_data:
  clickhouse_data:
```

### 9.2 Laptop Dependencies

```bash
# requirements.txt
redis>=5.0.0
httpx>=0.27.0
python-dotenv>=1.0.0
```

```bash
# Install scanners (example: Go-based tools)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### 9.3 Directory Structure

```
asm-pipeline/
├── plans/
│   └── phase_0              # This document
├── src/
│   ├── __init__.py
│   ├── config.py            # Env var loading
│   ├── scanner.py           # ToolRunner + tool wrappers
│   ├── normalizer.py        # EventNormalizer + dedup
│   ├── producer.py          # RedisEventProducer
│   ├── consumer.py          # StreamConsumer + ClickHouseIngester
│   ├── clickhouse_client.py # HTTP CH client
│   ├── safety.py            # Rate limiters, scope validation
│   └── orchestrator.py      # Main async loop
├── tests/
│   └── test_normalizer.py
├── .env                     # gitignored credentials
├── requirements.txt
└── Dockerfile.consumer      # Optional: run consumer on server
```

### 9.4 Run Commands

```bash
# 1. Start infrastructure (on remote server)
ssh user@192.168.1.21 "cd /opt/asm && docker-compose up -d"

# 2. Initialize ClickHouse schema
python src/init_schema.py

# 3. Run full pipeline (on laptop)
python src/orchestrator.py --target example.com --scan-id $(uuidgen)

# 4. Monitor (on remote server)
redis-cli -h 192.168.1.21 -a $PASS XLEN asm:events:v1
clickhouse-client --host 192.168.1.21 --query "SELECT count() FROM asm_pipeline.events"
```

---

## 10. SUCCESS CRITERIA VALIDATION

| Criteria | Validation Method |
|----------|-------------------|
| End-to-end event flow | Run subfinder → verify events in Redis via XLEN → verify events in CH via SELECT count() |
| Temporal ordering | SELECT event_id, scan_timestamp FROM events ORDER BY scan_timestamp LIMIT 10 |
| Deduplication | Run identical scan twice. Second run CH row count should not increase (or increase only if TTL expired). |
| Crash recovery | Kill producer mid-scan. Restart. Verify no duplicate events (already ACK'd) and new events resume. |
| Backpressure | Stop consumer. Run large scan. Verify Redis maxlen trims old events. Restart consumer, verify ingestion resumes. |
| Failure isolation | Block ClickHouse port. Verify consumer stops ACKing, Redis backlog grows, alerts logged. |

---

## APPENDIX A: SAMPLE CLICKHOUSE QUERIES

```sql
-- Event count by type, last 24h
SELECT event_type, count() 
FROM asm_pipeline.events 
WHERE scan_timestamp > now() - INTERVAL 24 HOUR
GROUP BY event_type;

-- All subdomains found for target
SELECT asset, source_tool, scan_timestamp
FROM asm_pipeline.events
WHERE event_type = 'SUBDOMAIN_FOUND' AND target = 'example.com'
ORDER BY scan_timestamp DESC;

-- Port distribution across IPs
SELECT data.ip, arrayJoin(JSONExtractArrayRaw(data.ports)) as port, count()
FROM asm_pipeline.events
WHERE event_type = 'PORT_FOUND'
GROUP BY data.ip, port;

-- Technology stack changes over time
SELECT 
    scan_timestamp,
    JSONExtractString(data, 'technologies') as techs
FROM asm_pipeline.events
WHERE event_type = 'SERVICE_DETECTED' AND asset = 'https://api.example.com'
ORDER BY scan_timestamp;
```

---

**END OF PHASE 0 PLAN**
