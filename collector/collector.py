import asyncio
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
import httpx

# Load configuration and schemas
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(BASE_DIR, "schemas", "payload_schema.json")
ALLOWLIST_PATH = os.path.join(BASE_DIR, "schemas", "allowlist_config.json")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collector_local.db")

with open(ALLOWLIST_PATH, "r") as f:
    ALLOWLIST_CONFIG = json.load(f)

# Regex patterns for secret scrubbing
SCRUB_PATTERNS = [
    (re.compile(p["regex"]), p["replacement"])
    for p in ALLOWLIST_CONFIG["scrubbing_patterns"]
]

class LocalCollector:
    def __init__(self, collector_id="col-mum-01", tenant_id="tenant-alpha", saas_url="http://127.0.0.1:8000"):
        self.collector_id = collector_id
        self.tenant_id = tenant_id
        self.region = "ap-south-1"
        self.source_tz = "+05:30"
        self.saas_url = saas_url
        self.api_token = "bearer-secret-token-cicada-2026"
        self.status = "HEALTHY"
        self.start_time = time.time()
        self.is_outage_simulated = False
        
        self.init_local_db()

    def init_local_db(self):
        """Initializes the local SQLite database for raw logs and outage buffering (WAL mode)."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        
        # Local raw storage (NEVER leaves Tier 1)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS local_raw_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_payload TEXT,
                has_secret INTEGER,
                created_at TEXT
            )
        """)
        
        # Outage Queue buffer for resilient transmission
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS outage_queue (
                payload_id TEXT PRIMARY KEY,
                payload_json TEXT,
                status TEXT,
                created_at TEXT,
                attempts INTEGER DEFAULT 0
            )
        """)
        
        # Egress proof audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS egress_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_id TEXT,
                raw_snippet TEXT,
                egress_snippet TEXT,
                sha256_hash TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()

    def scrub_text(self, text: str) -> str:
        """Applies regex scrubbers to sanitize secrets, passwords, IPs, and tokens."""
        if not isinstance(text, str):
            text = str(text)
        for pattern, replacement in SCRUB_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def pseudonymize(self, identifier: str) -> str:
        """Generates a salted, irreversible pseudonymous ID for hostnames/IPs."""
        salt = ALLOWLIST_CONFIG["pseudonymization"]["salt"]
        prefix = ALLOWLIST_CONFIG["pseudonymization"]["prefix"]
        digest = hashlib.sha256(f"{salt}:{identifier}".encode()).hexdigest()[:8]
        return f"{prefix}{digest}"

    def build_sanitized_payload(self, raw_input: dict) -> dict:
        """Enforces the strict allow-list schema, dropping any unapproved keys."""
        payload_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc).isoformat()
        
        # Extract metrics safely with strict numeric bounds
        raw_metrics = raw_input.get("metrics", {})
        metrics = {
            "cpu_usage_pct": float(max(0, min(100, raw_metrics.get("cpu_usage_pct", 15.0)))),
            "memory_usage_pct": float(max(0, min(100, raw_metrics.get("memory_usage_pct", 40.0)))),
            "disk_io_pct": float(max(0, min(100, raw_metrics.get("disk_io_pct", 10.0)))),
            "network_latency_ms": float(max(0, raw_metrics.get("network_latency_ms", 22.0))),
            "packet_loss_pct": float(max(0, min(100, raw_metrics.get("packet_loss_pct", 0.0)))),
            "bandwidth_mbps": float(max(0, raw_metrics.get("bandwidth_mbps", 150.0)))
        }

        # Security summary evaluated locally
        raw_sec = raw_input.get("security_summary", {})
        security_summary = {
            "auth_failure_count": int(raw_sec.get("auth_failure_count", 0)),
            "risk_level": str(raw_sec.get("risk_level", "LOW")),
            "anomaly_flag": bool(raw_sec.get("anomaly_flag", False))
        }

        # Queue depth check
        queue_depth = self.get_queue_depth()
        status = "BUFFERING" if self.is_outage_simulated or queue_depth > 0 else "HEALTHY"

        collector_health = {
            "status": status,
            "buffer_queue_depth": queue_depth,
            "version": "1.0.0",
            "uptime_seconds": int(time.time() - self.start_time)
        }

        payload = {
            "payload_id": payload_id,
            "collector_id": self.collector_id,
            "tenant_id": self.tenant_id,
            "region": self.region,
            "timestamp_utc": now_utc,
            "source_timezone": self.source_tz,
            "metrics": metrics,
            "security_summary": security_summary,
            "collector_health": collector_health
        }
        return payload

    def record_raw_and_egress_proof(self, raw_input: dict, egress_payload: dict):
        """Stores raw data locally in Tier 1 and creates an auditable egress proof entry."""
        raw_str = json.dumps(raw_input)
        egress_str = json.dumps(egress_payload)
        
        # Check if raw input contained secrets for demo proof
        has_secret = 1 if any(k in raw_str.lower() for k in ["password", "secret", "bearer", "token", "key"]) else 0
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 1. Store raw locally (never leaves)
        cursor.execute(
            "INSERT INTO local_raw_records (raw_payload, has_secret, created_at) VALUES (?, ?, ?)",
            (raw_str, has_secret, datetime.now(timezone.utc).isoformat())
        )
        
        # 2. Store audit record with SHA-256 integrity hash
        payload_hash = hashlib.sha256(egress_str.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO egress_audit_log (payload_id, raw_snippet, egress_snippet, sha256_hash, timestamp) VALUES (?, ?, ?, ?, ?)",
            (egress_payload["payload_id"], raw_str[:300], egress_str, payload_hash, egress_payload["timestamp_utc"])
        )
        
        conn.commit()
        conn.close()

    def get_queue_depth(self) -> int:
        """Returns the number of buffered payloads awaiting delivery."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM outage_queue WHERE status = 'PENDING'")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def buffer_payload(self, payload: dict):
        """Buffers a payload into the local SQLite outage queue."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO outage_queue (payload_id, payload_json, status, created_at) VALUES (?, ?, 'PENDING', ?)",
            (payload["payload_id"], json.dumps(payload), payload["timestamp_utc"])
        )
        conn.commit()
        conn.close()

    async def send_to_saas(self, payload: dict) -> bool:
        """Sends payload to Tier 2 SaaS over authenticated HTTPS link."""
        if self.is_outage_simulated:
            return False

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "X-Collector-Id": self.collector_id,
            "X-Tenant-Id": self.tenant_id
        }
        
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                res = await client.post(f"{self.saas_url}/api/v1/telemetry", json=payload, headers=headers)
                return res.status_code == 200
        except Exception:
            return False

    async def flush_outage_queue(self):
        """Batches and flushes buffered records upon SaaS reconnection with zero loss."""
        if self.is_outage_simulated:
            return

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT payload_id, payload_json FROM outage_queue WHERE status = 'PENDING' ORDER BY created_at ASC LIMIT 25")
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            return

        for pid, pjson in rows:
            payload = json.loads(pjson)
            success = await self.send_to_saas(payload)
            if success:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("DELETE FROM outage_queue WHERE payload_id = ?", (pid,))
                conn.commit()
                conn.close()
            else:
                # If still unreachable, halt flush and retry later
                break

    async def process_telemetry(self, raw_input: dict):
        """Complete local collector pipeline."""
        # 1. Sanitize & build allow-listed payload
        egress_payload = self.build_sanitized_payload(raw_input)
        
        # 2. Record raw in Tier 1 and log egress proof
        self.record_raw_and_egress_proof(raw_input, egress_payload)
        
        # 3. Transmit or buffer
        delivered = await self.send_to_saas(egress_payload)
        if not delivered:
            self.buffer_payload(egress_payload)
            self.status = "BUFFERING"
        else:
            self.status = "HEALTHY"
            # Trigger background flush if any backlog exists
            if self.get_queue_depth() > 0:
                await self.flush_outage_queue()

        return egress_payload
