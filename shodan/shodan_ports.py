import shodan
import json
import os
from dotenv import load_dotenv
from pathlib import Path

# --------------------------------------------------
# Load API key from shodan/.env
# --------------------------------------------------

env_path = Path(__file__).parent / ".env"
load_dotenv(env_path)

API_KEY = os.getenv("SHODAN_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "Missing SHODAN_API_KEY. "
        "Create shodan/.env with SHODAN_API_KEY=your_key"
    )

# --------------------------------------------------
# Initialize Shodan client
# --------------------------------------------------

api = shodan.Shodan(API_KEY)

# --------------------------------------------------
# Define ports of interest + service labels
# --------------------------------------------------

PORTS = {
    # --- real-world common ports (Shodan-realistic) ---
    80: "http",
    443: "https",
    22: "ssh",
    21: "ftp",

    # --- MTD lab ports (so attacks keep tracking mutations) ---
    8080: "http-alt",
    8081: "http-alt",
    8082: "http-alt",
    8083: "http-alt",
    8084: "http-alt",

    3001: "api",
    3002: "api",
    3003: "api",

    5400: "database",
    5401: "database",
    5402: "database",

    2200: "ssh",
    2201: "ssh",
    2202: "ssh",

    2100: "ftp",
    2101: "ftp",
    2102: "ftp",
}


# --------------------------------------------------
# Query Shodan using COUNT (no host data)
# --------------------------------------------------

raw_stats = {}

for port, service in PORTS.items():
    query = f"port:{port}"
    print(f"[+] Counting Shodan results for {query}")

    try:
        result = api.count(query)
        total = result.get("total", 0)
    except shodan.APIError as e:
        print(f"[!] Shodan API error for {query}: {e}")
        total = 0

    raw_stats[str(port)] = {
        "count": int(total),
        "service": service
    }

# --------------------------------------------------
# Save RAW stats to JSON (new format)
# --------------------------------------------------

output_path = Path(__file__).parent / "raw_port_stats.json"

with open(output_path, "w") as f:
    json.dump(raw_stats, f, indent=2)

print(f"[✓] Saved raw Shodan port stats to {output_path}")
