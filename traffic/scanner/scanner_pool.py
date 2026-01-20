# traffic/scanner/scanner_pool.py
import json, random, time, subprocess
from pathlib import Path

TARGET = "10.0.2.2"

# behavior knobs (scanner = cautious, sometimes triggers)
TOP_N_PORTS = 50
BURST_PORT_FRACTION = 0.15
BURST_ATTEMPTS = 8
BURST_SPACING = (0.6, 1.0)     # guaranteed < 10s window
PORT_SPACING = (2.0, 4.0)

# ---------------- load Shodan-derived scanner ports ----------------

DATA = Path("/data/scanner_ports.json")
dist = json.loads(DATA.read_text())

ports = [p for p, _ in dist][:min(TOP_N_PORTS, len(dist))]
random.shuffle(ports)

burst_ports = set(
    random.sample(
        ports,
        max(1, int(len(ports) * BURST_PORT_FRACTION))
    )
)

def scan_once(port: int):
    cmd = [
        "nmap", "-Pn", "-n",
        "-p", str(port),
        TARGET,
        "--max-retries", "0"
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ---------------- scanning loop ----------------

for port in ports:
    print(f"[SCANNER] scanning {port}")
    scan_once(port)

    if port in burst_ports:
        print(f"[SCANNER] burst recheck on {port}")
        for _ in range(BURST_ATTEMPTS - 1):
            time.sleep(random.uniform(*BURST_SPACING))
            scan_once(port)

    time.sleep(random.uniform(*PORT_SPACING))
