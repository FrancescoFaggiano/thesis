#!/usr/bin/env python3
"""
MTD Mutator:
- Periodically rotates service ports (time-driven)
- Reacts to detector trigger files in shared/ (immediate rotation)
- Updates shared/state.json when it mutates ports
- Exposes Prometheus metrics on METRICS_PORT
"""

import os
import time
import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from prometheus_client import start_http_server, Counter, Gauge

SHARED_DIR = Path("/app/shared")
STATE_FILE = SHARED_DIR / "state.json"
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9102"))
LOG_DIR = SHARED_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Mutation policy: port pools for each service type (extendable)
PORT_RANGES = {
    "web": [8080, 8090, 8100, 8110, 8120],
    "api": [3000, 3001, 3002, 3003],
    "database": [5400, 5401, 5402, 5403],
    "ssh": [2200, 2201, 2202, 2203],
    "ftp": [2100, 2101, 2102, 2103]
}

PORT_LIFETIME_SECONDS = int(os.environ.get("PORT_LIFETIME_SECONDS", "60"))
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "5"))

# metrics
mutation_counter = Counter("mtd_mutator_mutations_total", "Total mutations", ["service_name", "reason"])
current_port_gauge = Gauge("mtd_mutator_current_port", "Current port per service", ["service_name"])

def read_state():
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def write_state(state):
    # atomic write
    tmp = STATE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    tmp.replace(STATE_FILE)

def rotate_service(svc, reason="time_rotation"):
    svc_type = svc["type"]
    pool = PORT_RANGES.get(svc_type, [svc["current_port"]])
    choices = [p for p in pool if p != int(svc["current_port"])]
    if not choices:
        return False
    old = int(svc["current_port"])
    newp = random.choice(choices)
    svc["current_port"] = newp
    mutation_counter.labels(service_name=svc["name"], reason=reason).inc()
    current_port_gauge.labels(service_name=svc["name"]).set(newp)
    ts = datetime.now(timezone.utc).isoformat()
    # append to log
    with open(SHARED_DIR / "logs" / "mutations.log", "a") as fh:
        fh.write(f"{ts} {svc['id']} {svc['name']} {old} -> {newp} reason={reason}\n")
    return True

def scan_for_triggers():
    # look for files named detector_trigger_*.json in shared dir
    files = sorted(SHARED_DIR.glob("detector_trigger_*.json"))
    triggers = []
    for f in files:
        try:
            with open(f, "r") as fh:
                triggers.append(json.load(fh))
        except Exception:
            pass
        try:
            f.unlink()
        except Exception:
            pass
    return triggers

def main_loop():
    print(f"[MUTATOR] Starting metrics on :{METRICS_PORT}")
    start_http_server(METRICS_PORT)

    last_change = {}
    while True:
        try:
            state = read_state()
            services = state.get("services", [])
            # process detector triggers first (immediate rotations)
            triggers = scan_for_triggers()
            for t in triggers:
                sid = t.get("service_id")
                dst = t.get("dst_port")
                # find service and rotate it
                for svc in services:
                    if svc["id"] == sid:
                        if rotate_service(svc, reason=f"scan_trigger_from_{t.get('src')}_to_{dst}"):
                            last_change[sid] = datetime.now(timezone.utc)
                            print(f"[MUTATOR] Rotated {svc['name']} due to trigger")
            # time-driven rotations
            now = datetime.now(timezone.utc)
            for svc in services:
                sid = svc["id"]
                lc = last_change.get(sid, None)
                if lc is None:
                    # initialize
                    last_change[sid] = now
                    current_port_gauge.labels(service_name=svc["name"]).set(int(svc["current_port"]))
                    continue
                age = (now - last_change[sid]).total_seconds()
                if age >= PORT_LIFETIME_SECONDS:
                    if rotate_service(svc, reason="time_rotation"):
                        last_change[sid] = now
                        print(f"[MUTATOR] Time-rotated {svc['name']}")
            # persist state if changed - naive write each loop
            write_state(state)
        except Exception as e:
            print(f"[MUTATOR] error: {e}")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    # create default state if missing
    if not STATE_FILE.exists():
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({"services": []}, indent=2))
    main_loop()
