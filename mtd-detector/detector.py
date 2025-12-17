#!/usr/bin/env python3
"""
mtd-detector: runs in a privileged, host-network container.

Responsibilities:
- Set up iptables:
    * NFQUEUE rule for NEW TCP connections
    * MTD_REDIRECT chain for old->new port redirection
- Use NetfilterQueue + Scapy to inspect TCP SYN packets
- Detect scanning behavior (per-source sliding window threshold)
- Log every connection / event in shared/logs/traffic.log
- When a scan hits a *service port*:
    * write trigger JSON in shared/triggers/ for mutator
- When a scan hits an *unused port*:
    * add iptables DROP rule for that port
- Watch shared/state.json for port changes and:
    * add iptables REDIRECT old_port -> new_port
- Expose Prometheus metrics on METRICS_PORT
"""

import os
import time
import json
import shutil
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from prometheus_client import start_http_server, Counter, Gauge

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

# ---------------- CONFIG & PATHS ----------------

SHARED_DIR = Path("/app/shared")
STATE_FILE = SHARED_DIR / "state.json"
LOG_DIR = SHARED_DIR / "logs"
TRIG_DIR = SHARED_DIR / "triggers"
LOG_DIR.mkdir(parents=True, exist_ok=True)
TRIG_DIR.mkdir(parents=True, exist_ok=True)

METRICS_PORT = int(os.environ.get("METRICS_PORT", "9101"))
QUEUE_NUM = int(os.environ.get("QUEUE_NUM", "1"))
SLIDING_WINDOW_SECONDS = int(os.environ.get("SLIDING_WINDOW_SECONDS", "10"))
CONN_THRESHOLD = int(os.environ.get("CONN_THRESHOLD", "8"))
TRIGGER_COOLDOWN_SECONDS = int(os.environ.get("TRIGGER_COOLDOWN_SECONDS", "30"))

IPTABLES_CMD = shutil.which("iptables") or "/sbin/iptables"

# ---------------- PROMETHEUS METRICS ----------------

connections_total = Counter(
    "mtd_detector_connections_total",
    "Total NEW TCP connections seen",
    ["src_ip", "dst_port"]
)

scans_total = Counter(
    "mtd_detector_scans_total",
    "Number of scan triggers detected per source",
    ["src_ip", "dst_port"]
)

drops_total = Counter(
    "mtd_detector_dropped_ports_total",
    "Number of times a port was dropped due to being scanned",
    ["dst_port"]
)

redirects_total = Counter(
    "mtd_detector_redirects_total",
    "Number of old->new redirect rules installed",
    ["service_name"]
)

active_attackers_gauge = Gauge(
    "mtd_detector_active_attackers",
    "Number of sources currently over the scan threshold"
)

# ---------------- RUNTIME STATE ----------------

conn_events = defaultdict(deque)      # src_ip -> deque[timestamps]
recent_triggers = {}                  # src_ip -> last_trigger_time
known_ports = {}                      # service_id -> last_known_port

# ---------------- UTILITIES ----------------

def log_event(msg: str):
    ts = datetime.now(timezone.utc).isoformat()
    line = f"{ts} {msg}\n"
    with open(LOG_DIR / "traffic.log", "a") as f:
        f.write(line)
    print(f"[DETECTOR] {msg}")

def read_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"services": []}
    except Exception as e:
        log_event(f"ERROR reading state.json: {e}")
        return {"services": []}

def find_service_by_port(port: int):
    state = read_state()
    for svc in state.get("services", []):
        if int(svc.get("current_port", -1)) == port:
            return svc
    return None

def setup_iptables():
    # Create MTD_REDIRECT chain in nat table
    subprocess.run([IPTABLES_CMD, "-t", "nat", "-N", "MTD_REDIRECT"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Ensure PREROUTING jumps into MTD_REDIRECT
    subprocess.run([IPTABLES_CMD, "-t", "nat", "-C", "PREROUTING",
                    "-j", "MTD_REDIRECT"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([IPTABLES_CMD, "-t", "nat", "-I", "PREROUTING", "1",
                    "-j", "MTD_REDIRECT"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # NFQUEUE rule on INPUT + OUTPUT for NEW TCP
    for chain in ("INPUT", "OUTPUT"):
        subprocess.run([
            IPTABLES_CMD,
            "-I", chain, "-p", "tcp",
            "-m", "conntrack", "--ctstate", "NEW",
            "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM)
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    log_event("iptables MTD_REDIRECT chain + NFQUEUE rules (INPUT/OUTPUT) installed")

def add_redirect_rule(old_port: int, new_port: int, service_name: str):
    cmd = [
        IPTABLES_CMD, "-t", "nat", "-A", "MTD_REDIRECT",
        "-p", "tcp", "--dport", str(old_port),
        "-j", "REDIRECT", "--to-ports", str(new_port)
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    redirects_total.labels(service_name=service_name).inc()
    log_event(f"REDIRECT old_port={old_port} -> new_port={new_port} for {service_name}")

PROTECTED_PORTS = {9090, 9100, 9101, 9102, 443, 50000}

def drop_port(port: int):
    if port in PROTECTED_PORTS:
        log_event(f"SKIPPED drop on protected port {port}")
        return

    cmd = [IPTABLES_CMD, "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    drops_total.labels(dst_port=str(port)).inc()
    log_event(f"DROP rule added for unused/scanned port {port}")

# ---------------- NFQUEUE CALLBACK ----------------

def nfq_callback(nfpacket):
    print("[NFQUEUE] packets received")
    try:
        pkt = IP(nfpacket.get_payload())
    except Exception:
        nfpacket.accept()
        return

    if not pkt.haslayer(TCP):
        nfpacket.accept()
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    if (tcp.flags & 0x02) and not (tcp.flags & 0x10):  # SYN and not ACK
        src = ip.src
        dst_port = int(tcp.dport)

        now = datetime.now(timezone.utc)
        dq = conn_events[src]
        dq.append(now)
        cutoff = now - timedelta(seconds=SLIDING_WINDOW_SECONDS)
        while dq and dq[0] < cutoff:
            dq.popleft()

        connections_total.labels(src_ip=src, dst_port=str(dst_port)).inc()
        log_event(f"NEW_CONN src={src} dport={dst_port}")

        # Check threshold
        if len(dq) >= CONN_THRESHOLD:
            last = recent_triggers.get(src)
            if last and (now - last).total_seconds() < TRIGGER_COOLDOWN_SECONDS:
                nfpacket.accept()
                return

            svc = find_service_by_port(dst_port)
            if svc:
                # Write trigger for mutator
                trig = {
                    "time": now.isoformat(),
                    "src_ip": src,
                    "dst_port": dst_port,
                    "service_id": svc["id"]
                }
                trig_file = TRIG_DIR / f"scan_{int(now.timestamp())}_{src.replace('.', '_')}_{dst_port}.json"
                with open(trig_file, "w") as f:
                    json.dump(trig, f)
                scans_total.labels(src_ip=src, dst_port=str(dst_port)).inc()
                log_event(f"SCAN_TRIGGER src={src} dport={dst_port} service={svc['name']}")
            else:
                # Unused port: close it with DROP rule
                drop_port(dst_port)
            recent_triggers[src] = now

    nfpacket.accept()

# ---------------- WATCH STATE FOR MUTATIONS (REDIRECT) ----------------

def watch_state_for_redirects():
    """
    Watches shared/state.json for port changes.
    When a service's port changes from old->new:
      - install iptables REDIRECT old->new
      - log event + metrics
    """
    global known_ports
    last_mtime = STATE_FILE.stat().st_mtime if STATE_FILE.exists() else 0.0

    while True:
        try:
            if STATE_FILE.exists():
                mtime = STATE_FILE.stat().st_mtime
                if mtime != last_mtime:
                    last_mtime = mtime
                    state = read_state()
                    for svc in state.get("services", []):
                        sid = svc["id"]
                        name = svc["name"]
                        new_port = int(svc["current_port"])
                        old_port = known_ports.get(sid)
                        if old_port is None:
                            known_ports[sid] = new_port
                        elif old_port != new_port:
                            # Port changed: add redirect
                            add_redirect_rule(old_port, new_port, name)
                            known_ports[sid] = new_port
        except Exception as e:
            log_event(f"ERROR in watch_state_for_redirects: {e}")
        time.sleep(1.0)

# ---------------- MAIN ----------------

if __name__ == "__main__":
    print(f"[DETECTOR] Starting metrics on :{METRICS_PORT}")
    start_http_server(METRICS_PORT)

    setup_iptables()

    # Scan initial state to seed known_ports
    for svc in read_state().get("services", []):
        known_ports[svc["id"]] = int(svc["current_port"])

    # Start state watcher in background
    import threading
    t = threading.Thread(target=watch_state_for_redirects, daemon=True)
    t.start()

    nfq = NetfilterQueue()

    print("[DEBUG] About to bind NFQUEUE")
    nfq.bind(QUEUE_NUM, nfq_callback)
    print("[DEBUG] NFQUEUE bound successfully")

    log_event(f"NFQUEUE bound on queue {QUEUE_NUM}, listening for TCP SYNs")

    try:
        print("[DEBUG] Calling nfqueue.run()")
        nfq.run()
    except KeyboardInterrupt:
        log_event("Interrupted by user")
    finally:
        try:
            nfq.unbind()
        except Exception:
            pass
        log_event("Detector exiting")
