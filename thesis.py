#!/usr/bin/env python3
import random
import uuid
import threading
import subprocess
import sys
import os
import shutil
from datetime import datetime, timedelta, timezone

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

# ---------- CONFIG ----------
MTD_CONFIG = {
    "port_ranges": {
        "web": [8080, 8090, 8100, 8110, 8120],
        "database": [5400, 5401, 5402, 5403, 5404],
        "api": [3000, 3001, 3002, 3003, 3004],
        "ssh": [2200, 2201, 2202, 2203, 2204],
        "ftp": [2100, 2101, 2102, 2103, 2104]
    }
}

DETECTION = {
    "sliding_window_seconds": 10,
    "conn_threshold": 8,
    "queue_num": 1,
    "dry_run": False   # set True for safe testing (no iptables changes)
}

TRIGGER_COOLDOWN = timedelta(seconds=30)  # Prevents frequent mutations for same attacker.

# Track iptables rules we add
iptables_rules_added = []
nfqueue_rule_added = False

# Locate iptables binary
IPTABLES_CMD = shutil.which("iptables") or "/sbin/iptables"

# ---------- STATE ----------
class MTDState:
    def __init__(self):
        self.services = {}
        self.mutation_history = []
        self.last_mutation = datetime.now(timezone.utc)
        self.lock = threading.RLock()

    def initialize_services(self):
        services = [
            {"name": "Web Server", "type": "web"},
            {"name": "Database", "type": "database"},
            {"name": "API Gateway", "type": "api"},
            {"name": "SSH Service", "type": "ssh"},
            {"name": "FTP Server", "type": "ftp"}
        ]
        for svc in services:
            sid = str(uuid.uuid4())
            ports = MTD_CONFIG["port_ranges"][svc["type"]]
            self.services[sid] = {
                "id": sid,
                "name": svc["name"],
                "type": svc["type"],
                "current_port": random.choice(ports),
                "mutation_count": 0
            }

mtd_state = MTDState()
mtd_state.initialize_services()

print("\n=== Current Service Port Mapping ===")
for svc in mtd_state.services.values():
	print(f"{svc['name']:<15} | Type: {svc['type']:<10} | Port: {svc['current_port']}")
print ("====================================\n")


# Track per-source SYN events
conn_events = {}
recent_triggers = {}

# ---------- IPTABLES HELPERS ----------
def run_cmd(cmd: list) -> bool:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def setup_iptables_chain():
    global nfqueue_rule_added
    if DETECTION["dry_run"]:
        print("[IPTABLES] Dry-run: not creating MTD_REDIRECT chain or NFQUEUE rule")
        return

    # create chain if it doesn't exist (ignore errors)
    subprocess.run([IPTABLES_CMD, "-t", "nat", "-N", "MTD_REDIRECT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # insert jump from PREROUTING
    run_cmd([IPTABLES_CMD, "-t", "nat", "-I", "PREROUTING", "-j", "MTD_REDIRECT"])
    print("[IPTABLES] MTD_REDIRECT chain prepared")

    # add NFQUEUE rule for incoming NEW TCP connections (so our NFQUEUE sees SYNs)
    queue_num = str(DETECTION.get("queue_num", 1))
    nfq_cmd = [IPTABLES_CMD, "-I", "INPUT", "-p", "tcp", "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-num", queue_num]
    if run_cmd(nfq_cmd):
        nfqueue_rule_added = True
        print(f"[IPTABLES] NFQUEUE rule inserted (queue {queue_num})")
    else:
        print("[IPTABLES] Failed to insert NFQUEUE rule (you may need to add it manually)")

def add_redirect_rule(old_port: int, new_port: int) -> bool:
    if DETECTION["dry_run"]:
        print(f"[IPTABLES] Dry-run add redirect {old_port} -> {new_port}")
        return True
    cmd = [IPTABLES_CMD, "-t", "nat", "-A", "MTD_REDIRECT",
           "-p", "tcp", "--dport", str(old_port),
           "-j", "REDIRECT", "--to-ports", str(new_port)]
    ok = run_cmd(cmd)
    if ok:
        print(f"[IPTABLES] Added redirect {old_port} -> {new_port}")
    else:
        print(f"[IPTABLES] Failed to add redirect {old_port} -> {new_port}")
    return ok

def remove_nfqueue_rule():
    global nfqueue_rule_added
    if DETECTION["dry_run"]:
        print("[IPTABLES] Dry-run: NFQUEUE rule not removed (none added)")
        return
    if not nfqueue_rule_added:
        # try to remove generically in case it was added manually previously
        subprocess.run([IPTABLES_CMD, "-D", "INPUT", "-p", "tcp", "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-num", str(DETECTION.get("queue_num",1))], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    # remove the specific rule we added
    subprocess.run([IPTABLES_CMD, "-D", "INPUT", "-p", "tcp", "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-num", str(DETECTION.get("queue_num",1))], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    nfqueue_rule_added = False
    print("[IPTABLES] NFQUEUE rule removed")

def cleanup_iptables_chain():
    if DETECTION["dry_run"]:
        print("[IPTABLES] Dry-run: no cleanup")
        return
    # remove NFQUEUE rule first
    remove_nfqueue_rule()
    # remove MTD_REDIRECT jump and flush/delete chain
    subprocess.run([IPTABLES_CMD, "-t", "nat", "-D", "PREROUTING", "-j", "MTD_REDIRECT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([IPTABLES_CMD, "-t", "nat", "-F", "MTD_REDIRECT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([IPTABLES_CMD, "-t", "nat", "-X", "MTD_REDIRECT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[IPTABLES] Cleaned up MTD_REDIRECT chain and NFQUEUE rule")

# ---------- CORE MUTATION ----------
def mutate_service_port(service_id: str, reason: str = "event"):
    with mtd_state.lock:
        if service_id not in mtd_state.services:
            return False
        svc = mtd_state.services[service_id]
        available = [p for p in MTD_CONFIG["port_ranges"][svc["type"]] if p != svc["current_port"]]
        if not available:
            return False

        # Update service
        new_port = random.choice(available)
        old_port = svc["current_port"]
        svc["current_port"] = new_port
        svc["mutation_count"] += 1
        mtd_state.last_mutation = datetime.now(timezone.utc)
        event = {
            "id": str(uuid.uuid4()),
            "service_id": service_id,
            "service_name": svc["name"],
            "old_port": old_port,
            "new_port": new_port,
            "timestamp": mtd_state.last_mutation.isoformat(),
            "reason": reason
        }
        mtd_state.mutation_history.append(event)
        print(f"[MUTATION] {svc['name']} {old_port} -> {new_port} (reason={reason})")

        # Add iptables redirect from old -> new
        added = add_redirect_rule(old_port, new_port)
        if added:
            iptables_rules_added.append({"old": old_port, "new": new_port})

        return True

# ---------- NFQUEUE CALLBACK ----------
def nfq_packet_callback(nf_pkt):
    """
    If packet is NEW TCP, record event for source IP.
    Then if the number of events within the sliding window is > threshold, it triggers
    the mutation on a random active service.
    """
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

    # SYN and not ACK = new connection attempt
    if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
        src = ip.src
        dst_port= int(tcp.dport)
        now = datetime.now(timezone.utc)
        #record this event for sliding-window detection
        lst = conn_events.setdefault(src, [])
        lst.append(now)
        #drop old events outside the sliding window
        cutoff = now - timedelta(seconds=DETECTION["sliding_window_seconds"])
        while lst and lst[0] < cutoff:
            lst.pop(0)

	#if threshold is reached, check cooldown then trigger mutation
        if len(lst) >= DETECTION["conn_threshold"]:
            last_trig = recent_triggers.get(src)
            if not last_trig or now - last_trig > TRIGGER_COOLDOWN:
                # Trigger mutation
                with mtd_state.lock:
                    target_sid= None
                for sid, svc in mtd_state.services.items():
                    if svc.get('current_port') == dst_port:
                       target_sid= sid
                       break
                if target_sid:
                    mutate_service_port(target_sid, reason=f"scan_from_{src}_to_port_{dst_port}")
                    recent_triggers[src] = now
                else:
                    #I'm not sure this is a good idea, but it calls a random mutation if no service matched the scanned port
                    if mtd_state.services:
                       sid = random.choice(list(mtd_state.services.keys()))
                       mutate_service_port(sid, reason=f"scan_from_{src}_to_unknown_port_{dst_port}")
                       recent_triggers[src] = now

    nf_pkt.accept()

# ---------- NFQUEUE RUNNER ----------
def run_nfq(queue_num=1):
    nfq = NetfilterQueue()
    nfq.bind(queue_num, nfq_packet_callback)
    print(f"[NFQ] Listening on queue {queue_num} for TCP SYNs...")
    try:
        nfq.run()
    except KeyboardInterrupt:
        print("[STOP] NFQUEUE interrupted")
    finally:
        try:
            nfq.unbind()
        except Exception:
            pass
        cleanup_iptables_chain()

# ---------- MAIN ----------
if __name__ == "__main__":
    if not DETECTION["dry_run"] and not (os.geteuid() == 0):
        print("[FATAL] Must run as root (sudo) to use NFQUEUE + iptables")
        sys.exit(1)

    setup_iptables_chain()
    run_nfq(DETECTION["queue_num"])
