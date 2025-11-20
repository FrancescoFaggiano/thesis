#!/usr/bin/env python3
"""
MTD Detector (container):
- Binds to an NFQUEUE to observe NEW TCP SYN packets (requires privileged + host network)
- Tracks per-source SYN counts in a sliding window and writes triggers to shared/state.json or logs.
- Exposes Prometheus metrics on METRICS_PORT.
"""

import os
import time
import json
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from prometheus_client import start_http_server, Counter, Gauge

# netfilterqueue/scapy usage requires host privileges & kernel support.
try:
    from netfilterqueue import NetfilterQueue
    from scapy.all import IP, TCP
    NF_AVAILABLE = True
except Exception:
    NF_AVAILABLE = False

SHARED_DIR = Path("/app/shared")
STATE_FILE = SHARED_DIR / "state.json"
LOG_DIR = SHARED_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

METRICS_PORT = int(os.environ.get("METRICS_PORT", "9101"))

# Detection params (tweak via env vars or edit here)
SLIDING_WINDOW_SECONDS = int(os.environ.get("SLIDING_WINDOW_SECONDS", "10"))
CONN_THRESHOLD = int(os.environ.get("CONN_THRESHOLD", "8"))
QUEUE_NUM = int(os.environ.get("QUEUE_NUM", "1"))
TRIGGER_COOLDOWN_SECONDS = int(os.environ.get("TRIGGER_COOLDOWN_SECONDS", "30"))

# Metrics
scan_counter = Counter("mtd_detector_scans_total", "Total scan triggers", ["src"])
closed_port_counter = Counter("mtd_detector_closed_ports_total", "Closed ports due to scans")
current_attackers_gauge = Gauge("mtd_detector_active_attackers", "Approx. active attackers")

# runtime structures
conn_events = defaultdict(deque)
recent_triggers = {}

def read_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"services": []}

def find_service_by_port(port):
    state = read_state()
    for svc in state.get("services", []):
        if int(svc.get("current_port", -1)) == int(port):
            return svc
    return None

def log_trigger(src, dst_port):
    ts = datetime.now(timezone.utc).isoformat()
    LOG_DIR.joinpath("detector_events.log").write_text(f"{ts} TRIGGER {src} -> {dst_port}\n", append=True) if False else None

# NFQUEUE callback (best-effort; if NFQUEUE missing, run in simulation mode)
def nfq_packet_callback(nf_pkt):
    try:
        pkt = IP(nf_pkt.get_payload())
    except Exception:
        nf_pkt.accept()
        return

    if not pkt.haslayer(TCP):
        nf_pkt.accept()
        return
    tcp = pkt[TCP]
    ip = pkt[IP]
    # new connection (SYN, not ACK)
    if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
        src = ip.src
        dst_port = int(tcp.dport)
        now = datetime.now(timezone.utc)
        dq = conn_events[src]
        dq.append(now)
        cutoff = now - timedelta(seconds=SLIDING_WINDOW_SECONDS)
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= CONN_THRESHOLD:
            last = recent_triggers.get(src)
            if last and (now - last).total_seconds() < TRIGGER_COOLDOWN_SECONDS:
                pass
            else:
                # determine if the dst_port matches a service
                svc = find_service_by_port(dst_port)
                if svc:
                    # trigger: log and write to shared logs, increment metrics
                    scan_counter.labels(src=src).inc()
                    current_attackers_gauge.inc()
                    # For simplicity, write an event file; mutator/controller can react to this file
                    ev = {
                        "time": now.isoformat(),
                        "src": src,
                        "dst_port": dst_port,
                        "service_id": svc["id"]
                    }
                    with open(SHARED_DIR / f"detector_trigger_{int(now.timestamp())}.json", "w") as fh:
                        json.dump(ev, fh)
                    print(f"[DETECTOR] Trigger from {src} against port {dst_port} (service {svc['name']})")
                else:
                    # closed-port behavior: increment metric and write a 'closed_ports' suggestion
                    closed_port_counter.inc()
                    print(f"[DETECTOR] Scan on unused port {dst_port} from {src} (suggest close)")
                recent_triggers[src] = now
    nf_pkt.accept()

def run_nfqueue():
    if not NF_AVAILABLE:
        print("[DETECTOR] netfilterqueue or scapy not available in container; detector in simulation mode")
        return
    nfq = NetfilterQueue()
    nfq.bind(QUEUE_NUM, nfq_packet_callback)
    print(f"[DETECTOR] NFQUEUE bound to {QUEUE_NUM} - listening for TCP SYNs")
    try:
        nfq.run()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            nfq.unbind()
        except Exception:
            pass

if __name__ == "__main__":
    print(f"[DETECTOR] starting metrics on :{METRICS_PORT}")
    start_http_server(METRICS_PORT)

    # If NF unavailable, we still run, expecting offline testing
    if not NF_AVAILABLE:
        print("[DETECTOR] WARNING: NFQUEUE / Scapy not installed or kernel binding failed.")

    # run NFQUEUE loop (blocking)
    try:
        run_nfqueue()
    except Exception as e:
        print(f"[DETECTOR] Error: {e}")
    finally:
        print("[DETECTOR] exiting")
