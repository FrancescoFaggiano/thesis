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

# Build weighted pool
port_pool = []
for p,w in ports:
    port_pool.extend([p]*w)

ports_to_scan = random.sample(port_pool, min(scan_count, len(port_pool)))

print(f"[ATTACKER] Mode={mode} | Targets={len(ports_to_scan)}")

# Execute scanning
for port in ports_to_scan:
    print(f"[ATTACKER] scan {TARGET}:{port}")
    os.system(f"nmap -p {port} {TARGET}")
    time.sleep(random.uniform(min_delay, max_delay))
