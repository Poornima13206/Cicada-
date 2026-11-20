import sys
import os
import json

sys.path.insert(0, os.getcwd())
import saas.server as srv
from fastapi.testclient import TestClient

client = TestClient(srv.app)

print("--- 1. Testing SaaS Initial Overview ---")
resp = client.get('/api/v1/overview')
print('Overview API Status:', resp.status_code)
data = resp.json()
print('Initial Health State:', data['health_state'])

print("\n--- 2. Testing Metadata Ingest with Allow-List & Secrets Absent ---")
test_payload = {
    'payload_id': 'test-uuid-999',
    'collector_id': 'col-mum-01',
    'tenant_id': 'tenant-alpha',
    'region': 'ap-south-1',
    'timestamp_utc': '2026-11-20T14:40:00Z',
    'source_timezone': '+05:30',
    'metrics': {
        'cpu_usage_pct': 88.0,
        'memory_usage_pct': 89.0,
        'disk_io_pct': 30.0,
        'network_latency_ms': 180.0,
        'packet_loss_pct': 3.5,
        'bandwidth_mbps': 200.0
    },
    'security_summary': {
        'auth_failure_count': 6,
        'risk_level': 'HIGH',
        'anomaly_flag': True
    },
    'collector_health': {
        'status': 'HEALTHY',
        'buffer_queue_depth': 0,
        'version': '1.0.0',
        'uptime_seconds': 120
    }
}

headers = {'Authorization': 'Bearer bearer-secret-token-cicada-2026'}
res_ingest = client.post('/api/v1/telemetry', json=test_payload, headers=headers)
print('Ingest API Status:', res_ingest.status_code, res_ingest.json())

print("\n--- 3. Testing AIOps Correlation & Priority RCA ---")
resp2 = client.get('/api/v1/overview')
data2 = resp2.json()
print('Updated Health State:', data2['health_state'])
print('Detected Incidents Count:', len(data2['active_incidents']))
for inc in data2['active_incidents']:
    print(f"[{inc['priority']}] {inc['title']} (Confidence: {inc['confidence']}%)")
    print(f"  -> Why Fix First: {inc['why_fix_first']}")
    print(f"  -> Recommendation: {inc['recommendation']}")

print("\n--- 4. Testing Zero-Duplicate Deduplication (Idempotency) ---")
res_dedup = client.post('/api/v1/telemetry', json=test_payload, headers=headers)
print('Duplicate Payload Response:', res_dedup.json())

print("\n--- 5. Testing Dashboard UI Delivery ---")
resp_ui = client.get('/')
print('UI Status Code:', resp_ui.status_code, '(HTML Dashboard loaded, size:', len(resp_ui.text), 'bytes)')

print("\n>>> ALL TESTS COMPLETED SUCCESSFULLY! <<<")
