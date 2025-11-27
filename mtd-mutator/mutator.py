#!/usr/bin/env python3
"""
mtd-mutator:
- Periodically rotates service ports (time-based)
- Processes triggers from detector (scan-based)
- Updates shared/state.json
- Logs mutations to shared/logs/mutations.log
- Exposes Prometheus metrics on METRICS_PORT
"""

import os
import time
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from prometheus_client import start_http_server, Counter, Gauge

SHARED_DIR = Path("/app/shared")
STATE_FILE = SHARED_DIR / "state.json"
TRIG_DIR = SHARED_DIR / "triggers"
LOG_DIR = SHARED_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
TRIG_DIR.mkdir(parents=True, exist_ok=True)

METRICS_PORT = int(os.environ.get("METRICS_PORT", "9102"))
PORT_LIFETIME_SECONDS = int(os.environ.get("PORT_LIFETIME_SECONDS", "60"))
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "5"))

# Allowed port ranges by type (tweak to match your thesis)
PORT_RANGES = {
    "web": [8080, 8081, 8082, 8083, 8084],
    "api": [3000, 3001, 3002],
    "database": [5400, 5401, 5402],
    "ssh": [2200, 2201, 2202],
    "ftp": [2100, 2101, 2102]
}

mutation_counter = Counter(
    "mtd_mutator_mutations_total",
    "Number of port mutations",
    ["service_name", "reason"]
)

current_port_gauge = Gauge(
    "mtd_mutator_current_port",
    "Current port per service (view from mutator)",
    ["service_name"]
)

def log_mutation(msg: str):
    ts = datetime.now(timezone.utc).isoformat()
    with open(LOG_DIR / "mutations.log", "a") as f:
        f.write(f"{ts} {msg}\n")
    print(f"[MUTATOR] {msg}")

def read_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"services": []}

def write_state(state):
    tmp = STATE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    tmp.replace(STATE_FILE)

def rotate_service(svc, reason: str):
    svc_type = svc.get("type", "web")
    pool = PORT_RANGES.get(svc_type, [svc["current_port"]])
    current_port = int(svc["current_port"])
    choices = [p for p in pool if p != current_port]
    if not choices:
        return False

    new_port = random.choice(choices)
    old_port = current_port
    svc["current_port"] = new_port
    name = svc["name"]

    mutation_counter.labels(service_name=name, reason=reason).inc()
    current_port_gauge.labels(service_name=name).set(new_port)
    log_mutation(f"{name} {old_port} -> {new_port} reason={reason}")
    return True

def process_triggers(state, last_change):
    changed = False
    for trig_path in sorted(TRIG_DIR.glob("scan_*.json")):
        try:
            with open(trig_path, "r") as f:
                trig = json.load(f)
        except Exception:
            trig_path.unlink(missing_ok=True)
            continue

        sid = trig.get("service_id")
        src = trig.get("src_ip")
        dst = trig.get("dst_port")
        for svc in state.get("services", []):
            if svc["id"] == sid:
                if rotate_service(svc, f"scan_from_{src}_to_{dst}"):
                    last_change[sid] = datetime.now(timezone.utc)
                    changed = True
        trig_path.unlink(missing_ok=True)
    return changed

def main():
    print(f"[MUTATOR] Starting metrics on :{METRICS_PORT}")
    start_http_server(METRICS_PORT)

    last_change = {}
    while True:
        try:
            state = read_state()
            services = state.get("services", [])
            now = datetime.now(timezone.utc)

            # initialise gauges & timestamps for new services
            for svc in services:
                sid = svc["id"]
                if sid not in last_change:
                    last_change[sid] = now
                    current_port_gauge.labels(service_name=svc["name"]).set(int(svc["current_port"]))

            changed = False

            # scan-based triggers
            if process_triggers(state, last_change):
                changed = True

            # time-based rotation
            for svc in services:
                sid = svc["id"]
                lc = last_change.get(sid, now)
                age = (now - lc).total_seconds()
                if age >= PORT_LIFETIME_SECONDS:
                    if rotate_service(svc, "time_rotation"):
                        last_change[sid] = now
                        changed = True

            if changed:
                write_state(state)

        except Exception as e:
            print(f"[MUTATOR] ERROR: {e}")

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    if not STATE_FILE.exists():
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({"services": []}, indent=2))
    main()
