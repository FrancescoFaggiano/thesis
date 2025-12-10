#!/usr/bin/env python3
"""
mtd-controller:
- Reads shared/state.json
- Ensures one container per service, mapped to current_port
- Uses SERVICE_IMAGE env (built from services/simple_service)
- Exposes Prometheus metrics on METRICS_PORT
- Logs mutations detected via state changes (for correlation)
"""

import os
import time
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import docker
from prometheus_client import start_http_server, Counter, Gauge

SHARED_DIR = Path("/app/shared")
STATE_FILE = SHARED_DIR / "state.json"
LOG_DIR = SHARED_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
MUTATION_LOG = LOG_DIR / "mutations_controller.csv"

METRICS_PORT = int(os.environ.get("METRICS_PORT", "9100"))
SERVICE_IMAGE = os.environ.get("SERVICE_IMAGE", "mtd_simple_service:latest")

mutation_counter = Counter(
    "mtd_controller_mutations_total",
    "Mutations observed by controller via state.json changes",
    ["service_name"]
)

service_port_gauge = Gauge(
    "mtd_controller_service_port",
    "Current port for each service (view from controller)",
    ["service_name"]
)

active_containers_gauge = Gauge(
    "mtd_controller_active_containers",
    "Number of active decoy containers"
)

client = docker.from_env()
containers = {}  # service_id -> {container, port, name}
lock = threading.RLock()

def read_state():
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def write_mutation_log(ts, service_id, name, old_port, new_port, reason):
    header_needed = not MUTATION_LOG.exists()
    with open(MUTATION_LOG, "a") as f:
        if header_needed:
            f.write("timestamp,service_id,service_name,old_port,new_port,reason\n")
        f.write(f"{ts},{service_id},{name},{old_port},{new_port},{reason}\n")

def ensure_service_container(svc):
    sid = svc["id"]
    name = svc["name"]
    desired_port = int(svc["current_port"])
    cname = f"mtd_svc_{sid}"

    with lock:
        info = containers.get(sid)
        if info and info.get("port") == desired_port:
            return info["container"].id

        # If exists with wrong port, remove
        if info:
            try:
                info["container"].stop(timeout=1)
                info["container"].remove()
            except Exception:
                pass
            containers.pop(sid, None)
# Force cleanup of any stale Docker container with same name
        try:
            stale = client.containers.get(cname)
            stale.stop(timeout=1)
            stale.remove()
            print(f"[CONTROLLER] Removed stale container {cname}")
        except docker.errors.NotFound:
            pass
        except Exception as e:
            print(f"[CONTROLLER] Cleanup error for {cname}: {e}")

        # Start new container mapping 8000->desired_port
        try:
            cont = client.containers.run(
                SERVICE_IMAGE,
                detach=True,
                name=cname,
                ports={"8000/tcp": desired_port},
                auto_remove=False
            )
            containers[sid] = {"container": cont, "port": desired_port, "name": name}
            active_containers_gauge.set(len(containers))
            service_port_gauge.labels(service_name=name).set(desired_port)
            print(f"[CONTROLLER] Started {name} on host port {desired_port} (container {cont.id[:12]})")
            return cont.id
        except Exception as e:
            print(f"[CONTROLLER] Failed to start {name} on port {desired_port}: {e}")
            return ""

def reconcile_loop():
    while True:
        try:
            state = read_state()
            services = state.get("services", [])
            for svc in services:
                ensure_service_container(svc)
        except FileNotFoundError:
            print("[CONTROLLER] state.json not found yet")
        except Exception as e:
            print(f"[CONTROLLER] reconcile error: {e}")
        time.sleep(5)

def watch_state_mutations():
    mtime = STATE_FILE.stat().st_mtime if STATE_FILE.exists() else 0
    prev_ports = {}
    while True:
        try:
            if STATE_FILE.exists():
                new_mtime = STATE_FILE.stat().st_mtime
                if new_mtime != mtime:
                    mtime = new_mtime
                    state = read_state()
                    for svc in state.get("services", []):
                        sid = svc["id"]
                        name = svc["name"]
                        port = int(svc["current_port"])
                        prev = prev_ports.get(sid)
                        if prev is None:
                            prev_ports[sid] = port
                        elif prev != port:
                            ts = datetime.now(timezone.utc).isoformat()
                            prev_ports[sid] = port
                            mutation_counter.labels(service_name=name).inc()
                            write_mutation_log(ts, sid, name, prev, port, "state_change")
                            print(f"[CONTROLLER] Observed mutation {name}: {prev} -> {port}")
                            service_port_gauge.labels(service_name=name).set(port)
        except Exception as e:
            print(f"[CONTROLLER] mutation watcher error: {e}")
        time.sleep(1)

if __name__ == "__main__":
    print(f"[CONTROLLER] Starting metrics on :{METRICS_PORT}")
    start_http_server(METRICS_PORT)

    t1 = threading.Thread(target=reconcile_loop, daemon=True)
    t2 = threading.Thread(target=watch_state_mutations, daemon=True)
    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("[CONTROLLER] Shutting down")
        with lock:
            for sid, info in list(containers.items()):
                try:
                    info["container"].stop(timeout=1)
                    info["container"].remove()
                except Exception:
                    pass
