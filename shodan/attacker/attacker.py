import json, random, time, os

TARGET = "10.0.2.2"

# Load behavior profile
with open("/app/attack_profile.json") as f:
    profile = json.load(f)

scan_count = profile.get("scan_count", 50)
min_delay  = profile.get("min_delay", 1)
max_delay  = profile.get("max_delay", 3)
mode       = profile.get("mode", "default")

# Load Shodan ports
with open("/data/port_distribution.json") as f:
    ports = json.load(f)

# Memory-safe weighted sampling
ports_to_scan = random.choices(
    population=[p for p, w in ports],
    weights=[w for p, w in ports],
    k=min(scan_count, len(ports)) if scan_count <= 0 else scan_count
)

print(f"[ATTACKER] Mode={mode} | Targets={len(ports_to_scan)}")

# Execute scanning
for port in ports_to_scan:
    print(f"[ATTACKER] scan {TARGET}:{port}")
    os.system(f"nmap -p {port} {TARGET}")
    time.sleep(random.uniform(min_delay, max_delay))
