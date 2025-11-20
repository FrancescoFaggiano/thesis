#!/usr/bin/env python3
"""
MTD Controller (containerized)
- Reads shared/state.json to learn which services exist and their current ports.
- Spawns service containers (from the simple_service image) bound to the requested host port.
- Exposes Prometheus metrics on METRICS_PORT (default 9100).
- Logs mutations to shared/logs/mutations.csv
"""

import os
import time
import json
import uuid
import threading
from datetime import datetime, timezone
from pathlib import Path

import docker
from prometheus_client import start_http_server, Counter, Gauge

SHARED_DIR = Path("/app/shared")
STATE_FILE = SHARED_DIR / "state.json"
LOG_DIR = SHARED_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
MUTATION_LOG = LOG_DIR / "mutations.csv"

METRICS_PORT = int(os.environ.get("METRICS_PORT", "9100"))

# Prometheus metrics
mutation_counter = Counter("mtd_controller_mutations_total", "Total mutations", ["service_name", "reason"])
service_port_gauge = Gauge("mtd_controller_service_port", "Current port per service", ["service_name"])
active_containers_gauge = Gauge("mtd_controller_active_containers", "Number of active service containers")

# Docker client (uses mounted docker socket)
client = docker.from_env()

# Keep mapping service_id -> container info
containers = {}
lock = threading.RLock()

# utility
def read_state():
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def write_mutation_log(ts, service_id, service_name, old_port, new_port, reason, container_id):
    header_needed = not MUTATION_LOG.exists()
    with open(MUTATION_LOG, "a") as f:
        if header_needed:
            f.write("timestamp,service_id,service_name,old_port,new_port,reason,container_id\n")
        f.write(f"{ts},{service_id},{service_name},{old_port},{new_port},{reason},{container_id}\n")

def ensure_service_container(svc):
    """Ensure a Docker container is running for svc at host port svc['current_port']."""
    sid = svc["id"]
    desired_port = int(svc["current_port"])
    name = f"mtd_service_{sid}"

    with lock:
        info = containers.get(sid)
        if info:
            # check port matches; if not, remove and recreate
            if info.get("port") == desired_port:
                return info["container"].id
            # else restart on desired port
            try:
                info["container"].stop(timeout=1)
                info["container"].remove()
            except Exception:
                pass
            containers.pop(sid, None)

        # run container mapping container port 8000 -> host desired_port
        try:
            cont = client.containers.run(
                "mtd_simple_service:latest",
                detach=True,
                name=name,
                ports={"8000/tcp": desired_port},
                auto_remove=False
            )
            containers[sid] = {"container": cont, "port": desired_port, "name": name}
            active_containers_gauge.set(len(containers))
            service_port_gauge.labels(service_name=svc["name"]).set(desired_port)
            return cont.id
        except Exception as e:
            print(f"[CONTROLLER] Failed to start container for {sid} on port {desired_port}: {e}")
            return ""

def reconcile():
    """Main reconcile loop: read state.json and ensure containers match the state."""
    while True:
        try:
            state = read_state()
            services = state.get("services", [])
            for svc in services:
                sid = svc["id"]
                # ensure container is running at svc['current_port']
                old_port = None
                with lock:
                    prev = containers.get(sid)
                    if prev:
                        old_port = prev.get("port")
                cid = ensure_service_container(svc)
                if cid:
                    # if port changed, record mutation
                    with lock:
                        prev = containers.get(sid)
                        if prev and prev.get("port") != svc["current_port"]:
                            pass  # handled above
                # publish gauge
                service_port_gauge.labels(service_name=svc["name"]).set(int(svc["current_port"]))
        except FileNotFoundError:
            print("[CONTROLLER] state.json not found; will retry")
        except Exception as e:
            print(f"[CONTROLLER] reconcile error: {e}")
        time.sleep(5)

def watch_state_file():
    """Watch state file modification and record when ports change (log + metrics)."""
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
                            # update prev_ports
                            prev_ports[sid] = port
                            # mutation metric + log
                            mutation_counter.labels(service_name=name, reason="external_state_change").inc()
                            write_mutation_log(ts, sid, name, prev, port, "external_state_change", "")
                            print(f"[CONTROLLER] Detected port change {name}: {prev} -> {port}")
                            service_port_gauge.labels(service_name=name).set(port)
            else:
                # no state file; wait
                pass
        except Exception as e:
            print(f"[CONTROLLER] watch_state_file error: {e}")
        time.sleep(1)

if __name__ == "__main__":
    # start metrics
    print(f"[CONTROLLER] Starting Prometheus metrics on :{METRICS_PORT}")
    start_http_server(METRICS_PORT)

    # initial reconcile on startup
    t_reconcile = threading.Thread(target=reconcile, daemon=True)
    t_watch = threading.Thread(target=watch_state_file, daemon=True)
    t_reconcile.start()
    t_watch.start()

    # main loop keeps container alive
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("[CONTROLLER] Shutting down, stopping managed containers")
        with lock:
            for sid, info in list(containers.items()):
                try:
                    info["container"].stop(timeout=1)
                    info["container"].remove()
                except Exception:
                    pass
