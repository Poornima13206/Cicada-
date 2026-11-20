import asyncio
import os
import random
import sqlite3
import sys
import time

# Add collector directory to path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from collector.collector import LocalCollector

collector = LocalCollector(collector_id="col-mum-01", tenant_id="tenant-alpha", saas_url="http://127.0.0.1:8000")
SAAS_DB = os.path.join(BASE_DIR, "saas", "saas_platform.db")

def check_chaos_instruction():
    """Polls the chaos state from SaaS to react to judge button clicks."""
    if not os.path.exists(SAAS_DB):
        return None
    try:
        conn = sqlite3.connect(SAAS_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM chaos_state WHERE key = 'active_chaos'")
        row = cursor.fetchone()
        if row:
            val = row[0]
            if val not in ["outage_start", "outage_stop"]:
                # Clear one-time chaos
                cursor.execute("DELETE FROM chaos_state WHERE key = 'active_chaos'")
                conn.commit()
            conn.close()
            return val
        conn.close()
    except Exception:
        pass
    return None

async def run_telemetry_loop():
    print("🚀 [CICADA SIMULATOR] Telemetry stream running...")
    
    cpu_base = 25.0
    mem_base = 42.0

    while True:
        chaos = check_chaos_instruction()
        
        # Base realistic fluctuations
        cpu = round(cpu_base + random.uniform(-4, 5), 1)
        mem = round(mem_base + random.uniform(-1, 2), 1)
        latency = round(random.uniform(18.0, 24.0), 1)
        loss = 0.0
        auth_fails = 0
        risk_level = "LOW"
        anomaly_flag = False

        # Raw log data (Local Tier 1 only)
        raw_log = f"INFO: Node healthy. Process status OK. Connection count: {random.randint(40, 60)}"

        # ---------------------------------------------------------
        # React to Judge Scenarios
        # ---------------------------------------------------------
        if chaos == "secret":
            print("💥 [CHAOS TRIGGERED] Injected confidential secret into raw telemetry stream!")
            raw_log = "CRITICAL_LOG: DB connection failure for user 'postgres' password='SuperSecretPassword!2026' with token 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' at host 10.0.4.12"
        
        elif chaos == "latency":
            print("⚡ [CHAOS TRIGGERED] Spiking Network Latency and Packet Loss!")
            latency = 192.5
            loss = 3.8
            anomaly_flag = True

        elif chaos == "auth":
            print("🔒 [CHAOS TRIGGERED] Injected Brute-Force Auth Anomaly!")
            auth_fails = 8
            risk_level = "HIGH"
            anomaly_flag = True

        elif chaos == "outage_start":
            if not collector.is_outage_simulated:
                print("🔌 [CHAOS TRIGGERED] Simulated Network Outage to SaaS. Collector is now BUFFERING locally.")
                collector.is_outage_simulated = True

        elif chaos == "outage_stop":
            if collector.is_outage_simulated:
                print("🔄 [CHAOS TRIGGERED] Restoring SaaS connectivity. Flushing buffered backlog...")
                collector.is_outage_simulated = False
                await collector.flush_outage_queue()

        raw_telemetry = {
            "source_node": "node-db-primary-internal",
            "private_ip": "10.0.8.44",
            "raw_log_content": raw_log,
            "metrics": {
                "cpu_usage_pct": cpu,
                "memory_usage_pct": mem,
                "disk_io_pct": 12.0,
                "network_latency_ms": latency,
                "packet_loss_pct": loss,
                "bandwidth_mbps": 320.0
            },
            "security_summary": {
                "auth_failure_count": auth_fails,
                "risk_level": risk_level,
                "anomaly_flag": anomaly_flag
            }
        }

        # Process through local collector
        await collector.process_telemetry(raw_telemetry)
        await asyncio.sleep(2.0)

if __name__ == "__main__":
    asyncio.run(run_telemetry_loop())
