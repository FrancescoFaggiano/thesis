# traffic/scanner/scanner.py
import json, random, time, subprocess

TARGET = "10.0.2.2"

# behavior knobs (scanner = cautious but can still trigger sometimes)
TOP_N_PORTS = 50              # scan only top ports from distribution
BURST_PORT_FRACTION = 0.15    # fraction of ports to "recheck" in a burst
BURST_ATTEMPTS = 8            # this can trigger your 8 SYN / 10s rule
BURST_SPACING = (0.8, 1.2)    # seconds between attempts (keeps within 10s)
PORT_SPACING = (2.0, 4.0)     # base delay between different ports

with open("/data/port_distribution.json") as f:
    dist = json.load(f)

ports = [p for p, _ in dist][:TOP_N_PORTS]
random.shuffle(ports)

burst_ports = set(random.sample(ports, max(1, int(len(ports) * BURST_PORT_FRACTION))))

def scan_once(port: int):
    # -sS optional; use it if container is privileged
    cmd = ["nmap", "-Pn", "-p", str(port), TARGET, "--max-retries", "1"]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

for port in ports:
    print(f"[SCANNER] scanning {port}")
    scan_once(port)

    # occasionally do a "recheck burst" on a port (still plausible scanner behavior)
    if port in burst_ports:
        print(f"[SCANNER] burst recheck on {port}")
        for _ in range(BURST_ATTEMPTS - 1):  # already scanned once above
            time.sleep(random.uniform(*BURST_SPACING))
            scan_once(port)

    time.sleep(random.uniform(*PORT_SPACING))
