# CICADA 2026: End-to-End Secure AIOps Observability Platform
**Core Direction:** Local-First Security | Metadata-Only SaaS | AIOps Event Intelligence | Global-Ready

---

## 🚀 How to Run the Platform on Your System

### 1-Click Launch:
Double-click `run_cicada.bat` OR run the command below in your PowerShell / Command Prompt terminal:

```bash
python start_platform.py
```

### Accessing the Web Dashboard:
Once running, open your web browser and navigate to:
👉 **http://127.0.0.1:8000**

---

## 🎯 What Was Built & Where It Lives

### 1. Phase 2 Architecture & Judge Defense (`docs/`)
- [docs/ARCHITECTURE.md](file:///c:/Users/poorn/OneDrive/Desktop/hackathon/docs/ARCHITECTURE.md): The Master Technical Design document with labeled trust boundary, network hops, local buffering, tenant isolation, and AIOps correlation algorithms.
- [docs/PHASE_2_DEFENSE_GUIDE.md](file:///c:/Users/poorn/OneDrive/Desktop/hackathon/docs/PHASE_2_DEFENSE_GUIDE.md): Cheat-sheet answering every question the judges will ask during the evaluation checkpoint.

### 2. Strict Zero-Trust Schemas (`schemas/`)
- [schemas/payload_schema.json](file:///c:/Users/poorn/OneDrive/Desktop/hackathon/schemas/payload_schema.json): Formal JSON Schema for metadata egress (`additionalProperties: false`).
- [schemas/allowlist_config.json](file:///c:/Users/poorn/OneDrive/Desktop/hackathon/schemas/allowlist_config.json): Allow-list configuration, regex secret scrubbers, and SHA-256 pseudonymization rules.

### 3. Tier 1: Local Collector (`collector/`)
- [collector/collector.py](file:///c:/Users/poorn/OneDrive/Desktop/hackathon/collector/collector.py):
  - Ingestion, parsing, and aggregation.
  - Secret scrubber: Redacts passwords, Bearer tokens, private IPs.
  - Strict allow-list enforcement: Drops non-whitelisted keys.
  - Local SQLite WAL storage: Kept strictly local (never leaves on-prem).
  - Outage Queue: Buffers payloads during SaaS downtime.
  - Egress Proof Logger: Real-time audit log with SHA-256 integrity hashes.

### 4. Tier 2: SaaS Multi-Tenant Platform & AIOps Engine (`saas/`)
- [saas/server.py](file:///c:/Users/poorn/OneDrive/Desktop/hackathon/saas/server.py):
  - Regional Ingestion Gateway (`/api/v1/telemetry`) with Bearer auth.
  - Idempotency & Deduplication: Checks `payload_id` to guarantee zero duplicates.
  - Out-of-Order Handling: Indexes metrics by event time (`timestamp_utc`).
  - 4-State Health Evaluation: Classifies nodes into `Excellent`, `Good`, `Fair`, `Poor` with automatic 30s/60s stale data degradation.
  - AIOps Incident Correlation: Multi-signal clustering (noise reduction).
  - Priority & Blast-Radius Engine: Ranks alerts from P1 to P4 with "Why Fix This First" explainability and Root Cause Analysis.
  - Integrated Web Console at `GET /`.

### 5. Telemetry & Chaos Simulator (`simulator/`)
- [simulator/stream_generator.py](file:///c:/Users/poorn/OneDrive/Desktop/hackathon/simulator/stream_generator.py):
  - Generates realistic telemetry streams.
  - Listens to the Web Console's Judge Testing Bar to trigger live scenarios:
    1. **Inject Secret:** Proves the local scrubber prevents secrets from reaching SaaS.
    2. **Spike Latency:** Demonstrates AIOps correlating latency + loss into a P1 Incident.
    3. **Brute Force Anomaly:** Triggers local risk indicators without exporting user passwords.
    4. **Cut SaaS Link:** Simulates network outage -> Collector queues locally -> SaaS drops to *Poor* -> Reconnect flushes queue with zero loss and zero duplicates.
