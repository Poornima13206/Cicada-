import subprocess
import sys
import time
import os

print("="*70)
print("  CICADA 2026: Two-Tier AIOps Observability Platform Launch Controller")
print("="*70)

base_dir = os.path.dirname(os.path.abspath(__file__))
saas_script = os.path.join(base_dir, "saas", "server.py")
sim_script = os.path.join(base_dir, "simulator", "stream_generator.py")

# Ensure project root is in PYTHONPATH
env = os.environ.copy()
env["PYTHONPATH"] = base_dir

# Launch SaaS
print("1. Starting SaaS Central Platform on http://127.0.0.1:8000 ...")
saas_proc = subprocess.Popen([sys.executable, saas_script], env=env)
time.sleep(2)

# Launch Simulator / Collector
print("2. Starting Tier 1 Collector & Telemetry Stream Generator ...")
sim_proc = subprocess.Popen([sys.executable, sim_script], env=env)

print("\n🚀 CICADA Observability Platform is LIVE!")
print("👉 Open in your browser:  http://127.0.0.1:8000")
print("👉 Live Egress Proof:     http://127.0.0.1:8000/api/v1/egress-proof")
print("👉 4-State Health API:    http://127.0.0.1:8000/api/v1/overview")
print("\nPress Ctrl+C in this terminal to safely stop all services.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nShutting down CICADA services...")
    saas_proc.terminate()
    sim_proc.terminate()
    print("Clean shutdown complete.")
