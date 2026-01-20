import json
from pathlib import Path

# Anchor paths to repo root
BASE = Path(__file__).resolve().parents[1]

RAW = BASE / "shodan" / "raw_port_stats.json"
OUT = BASE / "traffic" / "data" / "scanner_ports.json"

raw = json.loads(RAW.read_text())

# Extract (port, popularity) pairs for scanner
ports = [(int(p), v["count"]) for p, v in raw.items()]

# Sort by popularity (descending)
ports.sort(key=lambda x: x[1], reverse=True)

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(ports, indent=2))

print(f"[✓] Wrote {OUT}")
