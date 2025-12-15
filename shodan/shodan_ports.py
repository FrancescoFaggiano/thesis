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
# Define queries (ports of interest)
# --------------------------------------------------

ports = [
    22,    # SSH
    80,    # HTTP
    443,   # HTTPS
    21,    # FTP
    8080,  # Alt HTTP
]

# --------------------------------------------------
# Query Shodan using COUNT (no host data)
# --------------------------------------------------

port_distribution = []

for port in ports:
    query = f"port:{port}"
    print(f"[+] Counting Shodan results for {query}")

    try:
        result = api.count(query)
        total = result.get("total", 0)
    except shodan.APIError as e:
        print(f"[!] Shodan API error for {query}: {e}")
        total = 0

    port_distribution.append([port, total])

# --------------------------------------------------
# Save distribution to JSON
# --------------------------------------------------

output_path = Path(__file__).parent / "port_distribution.json"

with open(output_path, "w") as f:
    json.dump(port_distribution, f, indent=2)

print(f"[✓] Saved port distribution to {output_path}")
