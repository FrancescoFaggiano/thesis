#!/usr/bin/env python3
"""
MTD with Docker-simulated services + CSV logging of mutation events and container IDs.

- Docker containers simulate the real services (web, db, api, ssh, ftp).
- Containers persist while the service is assigned to a port; when the service
  is mutated to a new port, the previous container is stopped/removed and a
  new container is started on the new port.
- If an external scan targets a port that does NOT match any service, we only
  close the port (iptables DROP) and do NOT spawn a container.
- All mutation events are appended to a CSV file for experiment analysis.
"""

import random
import uuid
import threading
import subprocess
import sys
import os
import shutil
import csv
from datetime import datetime, timedelta, timezone

# docker SDK might be optional during dry-run
try:
    import docker
except Exception:
    docker = None

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

# ---------- CONFIG ----------
MTD_CONFIG = {
    "port_ranges": {
        "web": [80, 8080, 8090, 8100, 8110, 8120],
        "database": [5400, 5401, 5402, 5403, 5404],
        "api": [3000, 3001, 3002, 3003, 3004],
        "ssh": [22, 2200, 2201, 2202, 2203, 2204],
        "ftp": [21, 2100, 2101, 2102, 2103, 2104]
    }
}

DETECTION = {
    "sliding_window_seconds": 10,  # observation window
    "conn_threshold": 8,           # triggers if >= 8 SYNs in sliding window
    "queue_num": 1,
    "dry_run": True   # Default: True. Set False to enable iptables/Docker changes.
}

TRIGGER_COOLDOWN = timedelta(seconds=30)  # avoid flapping on same attacker

# Track iptables rules we add
iptables_rules_added = []
nfqueue_rule_added = False

# Locate iptables binary
IPTABLES_CMD = shutil.which("iptables") or "/sbin/iptables"

# ---------- LOGGING (CSV) ----------
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)

MUTATION_LOG_FILE = os.path.join(LOG_DIR, f"mtd_mutation_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv")

# create header if file missing
if not os.path.exists(MUTATION_LOG_FILE):
    with open(MUTATION_LOG_FILE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "timestamp",
            "service_id",
            "service_name",
            "old_port",
            "new_port",
            "reason",
            "container_id"   # NEW container id after mutation (if available)
        ])

def log_mutation(timestamp: datetime, service_id: str, service_name: str, old_port, new_port, reason: str, container_id: str):
    """Append a mutation event to the CSV log."""
    with open(MUTATION_LOG_FILE, "a", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            timestamp.astimezone(timezone.utc).isoformat(),
            service_id,
            service_name,
            old_port if old_port is not None else "",
            new_port if new_port is not None else "",
            reason,
            container_id or ""
        ])

# ---------- STATE ----------
class MTDState:
    def __init__(self):
        self.services = {}           # service_id -> service dict
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
            default_port = ports[0]
            self.services[sid] = {
                "id": sid,
                "name": svc["name"],
                "type": svc["type"],
                "current_port": default_port,
                "mutation_count": 0,
                "last_change": datetime.now(timezone.utc)
            }

mtd_state = MTDState()
mtd_state.initialize_services()

print("\n=== Current Service Port Mapping ===")
for svc in mtd_state.services.values():
    print(f"{svc['name']:<15} | Type: {svc['type']:<10} | Port: {svc['current_port']}")
print("====================================\n")


# Track per-source SYN events
conn_events = {}
recent_triggers = {}

# ---------- DOCKER MANAGER (services simulated persistently) ----------
class DockerManager:
    """
    Manage containers that simulate services. Containers persist as long as the
    simulated service runs on a port. When the service moves, the container is
    restarted on the new port.
    """
    def __init__(self):
        if docker is None:
            print("[DOCKER] docker SDK not available; DockerManager disabled")
            self.client = None
        else:
            try:
                self.client = docker.from_env()
            except Exception as e:
                print(f"[DOCKER] Failed to connect to Docker daemon: {e}")
                self.client = None
        # Map service_id -> container metadata
        self.service_containers = {}
        self.lock = threading.RLock()

    def spawn_service_container(self, service_id: str, service_type: str, host_port: int):
        """
        Start a container that simulates the service_type bound to host_port.
        Returns container.id or None on failure.
        Containers are persistent until stopped (no auto-remove).
        """
        if DETECTION["dry_run"]:
            print(f"[DOCKER] Dry-run: would spawn {service_type} for service {service_id} on port {host_port}")
            return None
        if not self.client:
            print("[DOCKER] Docker client unavailable; cannot spawn simulated service")
            return None

        container_port = host_port
        if service_type in ("web", "api"):
            if service_type == "web":
                body = "<html><body><h1>Fake Web</h1></body></html>"
                content_type = "text/html"
            else:
                body = '{"message":"fake api","status":"ok"}'
                content_type = "application/json"
            script = (
                "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
                "class H(BaseHTTPRequestHandler):\n"
                "    def do_GET(self):\n"
                f"        self.send_response(200)\n"
                f"        self.send_header('Content-Type','{content_type}')\n"
                "        self.end_headers()\n"
                f"        self.wfile.write(b'''{body}''')\n"
                "HTTPServer(('', %d), H).serve_forever()\n" % container_port
            )
            cmd = ["python", "-u", "-c", script]

        elif service_type in ("ssh", "ftp", "database"):
            if service_type == "ssh":
                banner = b"SSH-2.0-OpenSSH_7.9p1 FakeSSH\r\n"
            elif service_type == "ftp":
                banner = b"220 FakeFTP Service ready.\r\n"
            else:
                banner = b"FAKE-DB-OK\n"
            script = (
                "import socket\n"
                "s=socket.socket()\n"
                "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                "s.bind(('', %d))\n"
                "s.listen(5)\n"
                "while True:\n"
                "    c,addr=s.accept()\n"
                "    try:\n"
                "        c.send(%r)\n"
                "        c.settimeout(5)\n"
                "        while True:\n"
                "            data=c.recv(1024)\n"
                "            if not data: break\n"
                "            c.send(b'ACK:'+data[:64])\n"
                "    except Exception:\n"
                "        pass\n"
                "    finally:\n"
                "        try: c.close()\n"
                "        except: pass\n" % (container_port, banner)
            )
            cmd = ["python", "-u", "-c", script]
        else:
            print(f"[DOCKER] Unknown service_type: {service_type}")
            return None

        name = f"sim_{service_type}_{host_port}_{uuid.uuid4().hex[:6]}"
        try:
            with self.lock:
                container = self.client.containers.run(
                    "python:3.11-slim",
                    cmd,
                    detach=True,
                    name=name,
                    ports={f"{container_port}/tcp": host_port},
                    auto_remove=False,  # we remove explicitly on service move/shutdown
                    tty=False
                )
                self.service_containers[service_id] = {
                    "container_id": container.id,
                    "name": name,
                    "type": service_type,
                    "port": host_port,
                    "started": datetime.now(timezone.utc)
                }
            print(f"[DOCKER] Spawned simulated service {service_type} for {service_id} on host port {host_port} (container {container.id[:12]})")
            return container.id
        except Exception as e:
            print(f"[DOCKER] Error spawning simulated service: {e}")
            return None

    def stop_and_remove_container_for_service(self, service_id: str):
        """Stop & remove the container currently mapped to service_id, if any."""
        with self.lock:
            info = self.service_containers.pop(service_id, None)
        if not info:
            return
        try:
            c = self.client.containers.get(info["container_id"])
            try:
                c.stop(timeout=1)
            except Exception:
                pass
            try:
                c.remove()
            except Exception:
                pass
            print(f"[DOCKER] Stopped & removed container {info['container_id'][:12]} for service {service_id}")
        except Exception as e:
            print(f"[DOCKER] Failed to stop/remove container for service {service_id}: {e}")

    def move_service(self, service_id: str, new_port: int):
        """
        Stop old container, spawn a new one on new_port for given service_id.
        Returns True on success (or if dry-run), False on fatal error.
        """
        with self.lock:
            svc = mtd_state.services.get(service_id)
            if not svc:
                return False
            service_type = svc["type"]
        # stop old container first
        self.stop_and_remove_container_for_service(service_id)
        # spawn new container on new_port
        cid = self.spawn_service_container(service_id, service_type, new_port)
        return True if (DETECTION["dry_run"] or cid) else False

    def spawn_all_initial_services(self):
        """Spawn containers for every service in mtd_state (called at startup)."""
        for sid, svc in mtd_state.services.items():
            cid = self.spawn_service_container(sid, svc["type"], svc["current_port"])
            # Log initial spawn as an "initial_spawn" mutation event with container_id (if available)
            log_mutation(datetime.now(timezone.utc), sid, svc["name"], "", svc["current_port"], "initial_spawn", cid if cid else "")

    def stop_all(self):
        """Stop and remove all service containers managed by this manager."""
        with self.lock:
            sids = list(self.service_containers.keys())
        for sid in sids:
            self.stop_and_remove_container_for_service(sid)


docker_manager = DockerManager()

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
        iptables_rules_added.append({"old": old_port, "new": new_port})
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
        subprocess.run([IPTABLES_CMD, "-D", "INPUT", "-p", "tcp", "-m", "conntrack", "--ctstate", "NEW", "-j", "NFQUEUE", "--queue-num", str(DETECTION.get("queue_num",1))], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
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
    # Also remove individual redirect rules we tracked (best-effort)
    for r in iptables_rules_added:
        subprocess.run([IPTABLES_CMD, "-t", "nat", "-D", "MTD_REDIRECT", "-p", "tcp", "--dport", str(r["old"]), "-j", "REDIRECT", "--to-ports", str(r["new"])], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[IPTABLES] Cleaned up MTD_REDIRECT chain and NFQUEUE rule")

# ---------- CORE MUTATION ----------
def mutate_service_port(service_id: str, reason: str = "event"):
    """
    Move a simulated service to a new port:
      - pick new_port from allowed range (not the current)
      - update in-memory state
      - spawn container on new_port and stop old container via docker_manager.move_service()
      - add iptables redirect old->new (optional; helpful so existing clients hitting old port still reach new)
      - log the event to CSV along with the new container ID (if available)
    """
    with mtd_state.lock:
        if service_id not in mtd_state.services:
            return False
        svc = mtd_state.services[service_id]
        available = [p for p in MTD_CONFIG["port_ranges"][svc["type"]] if p != svc["current_port"]]
        if not available:
            return False

        new_port = random.choice(available)
        old_port = svc["current_port"]
        svc["current_port"] = new_port
        svc["mutation_count"] += 1
        mtd_state.last_mutation = datetime.now(timezone.utc)
        svc["last_change"] = mtd_state.last_mutation
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

    # spawn container on new port and stop previous container
    moved = docker_manager.move_service(service_id, new_port)
    # Attempt to fetch the new container_id (if any)
    container_id = ""
    if not DETECTION["dry_run"]:
        with docker_manager.lock:
            info = docker_manager.service_containers.get(service_id)
            if info:
                container_id = info.get("container_id", "")

    if not moved and not DETECTION["dry_run"]:
        print(f"[DOCKER] Warning: failed to move container for service {service_id} to {new_port}")

    # add iptables redirect old -> new to maintain reachability for clients hitting the old port
    added = add_redirect_rule(old_port, new_port)

    # Log the mutation with container ID
    log_mutation(mtd_state.last_mutation, service_id, svc["name"], old_port, new_port, reason, container_id)

    return True

def close_port(port: int):
    """
    Close a scanned unused port by adding a DROP rule in iptables.
    No container is spawned for scanned-but-unused ports (per your requirement).
    """
    if DETECTION["dry_run"]:
        print(f"[IPTABLES] Dry-run: would close port {port}")
        return True
    cmd = [IPTABLES_CMD, "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"]
    ok = run_cmd(cmd)
    if ok:
        print(f"[IPTABLES] Closed unused/scanned port {port}")
    else:
        print(f"[IPTABLES] Failed to close port {port}")
    return ok

# ---------- NFQUEUE CALLBACK ----------
def nfq_packet_callback(nf_pkt):
    """
    If packet is NEW TCP, record event for source IP.
    When suspicious, if the dst_port matches a simulated service -> trigger mutation.
    If dst_port does not match any simulated service -> close the port (DROP) and do not spawn containers.
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
        dst_port = int(tcp.dport)
        now = datetime.now(timezone.utc)
        lst = conn_events.setdefault(src, [])
        lst.append(now)
        cutoff = now - timedelta(seconds=DETECTION["sliding_window_seconds"])
        while lst and lst[0] < cutoff:
            lst.pop(0)

        if len(lst) >= DETECTION["conn_threshold"]:
            last_trig = recent_triggers.get(src)
            if not last_trig or now - last_trig > TRIGGER_COOLDOWN:
                # Find service that currently uses dst_port
                target_sid = None
                with mtd_state.lock:
                    for sid, svc in mtd_state.services.items():
                        if svc.get('current_port') == dst_port:
                            target_sid = sid
                            break
                if target_sid:
                    # rotate that service's port
                    mutate_service_port(target_sid, reason=f"scan_from_{src}_to_port_{dst_port}")
                else:
                    # No service matched scanned port -> close the port (no decoy)
                    close_port(dst_port)
                    print(f"[SECURITY] Scan detected from {src} on unused port {dst_port} - port closed (no container spawned)")
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

# ---------- TIME-DRIVEN MANAGER ----------
PORT_LIFETIME_SECONDS = 60   # how long a service port stays before rotation (time-driven)
CHECK_INTERVAL_SECONDS = 5

class PortManager(threading.Thread):
    """
    Periodically rotates services that have been on the same port for too long.
    """
    def __init__(self, state: MTDState):
        super().__init__(daemon=True)
        self.state = state
        self.running = True

    def run(self):
        print("[MANAGER] Time-driven port manager started")
        while self.running:
            now = datetime.now(timezone.utc)
            with self.state.lock:
                for sid, svc in list(self.state.services.items()):
                    if "last_change" not in svc:
                        svc["last_change"] = now
                    age = (now - svc["last_change"]).total_seconds()
                    if age >= PORT_LIFETIME_SECONDS:
                        print(f"[MANAGER] Rotating {svc['name']} (port {svc['current_port']}) due to timeout")
                        if mutate_service_port(sid, reason="time_rotation"):
                            svc["last_change"] = datetime.now(timezone.utc)
            threading.Event().wait(CHECK_INTERVAL_SECONDS)

    def stop(self):
        self.running = False

# ---------- MAIN ----------
if __name__ == "__main__":
    # Note: must be root to modify iptables / NFQUEUE; for testing use dry_run=True.
    if not DETECTION["dry_run"] and not (os.geteuid() == 0):
        print("[FATAL] Must run as root (sudo) to use NFQUEUE + iptables")
        sys.exit(1)

    # Setup iptables/NFQUEUE (or skip in dry-run)
    setup_iptables_chain()

    # Spawn one simulated container per service (unless dry-run) and log initial spawns
    docker_manager.spawn_all_initial_services()

    # Start manager thread
    port_manager = PortManager(mtd_state)
    port_manager.start()

    try:
        run_nfq(DETECTION["queue_num"])
    except KeyboardInterrupt:
        print("[STOP] Interrupted by user")
    finally:
        # Stop time manager
        port_manager.stop()
        # Stop all simulated service containers (if any)
        try:
            if not DETECTION["dry_run"] and docker_manager.client:
                docker_manager.stop_all()
        except Exception as e:
            print(f"[DOCKER] Error during shutdown: {e}")
        cleanup_iptables_chain()
        print(f"[EXIT] Shutdown complete. Mutation log saved to: {MUTATION_LOG_FILE}")
