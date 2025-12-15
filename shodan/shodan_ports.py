import shodan
import json
import os
from collections import Counter
from dotenv import load_dotenv
from pathlib import Path

# --------------------------------------------------
# Load API key from shodan/.env (local, gitignored)
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
# Define queries (focused on common exposed services)
# --------------------------------------------------

queries = [
    "port:22",    # SSH
    "port:80",    # HTTP
    "port:443",   # HTTPS
    "port:8080",  # Alt HTTP
    "port:21"     # FTP
]

# --------------------------------------------------
# Collect port frequencies
# --------------------------------------------------

ports_counter = Counter()

for query in queries:
    print(f"[+] Querying Shodan: {query}")
    try:
        results = api.search(query, limit=500)
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}")
        continue

    for host in results.get("matches", []):
        port = host.get("port")
        if port:
            ports_counter[port] += 1

# --------------------------------------------------
# Save distribution to JSON
# --------------------------------------------------

output_path = Path(__file__).parent / "port_distribution.json"

with open(output_path, "w") as f:
    json.dump(ports_counter.most_common(), f, indent=2)

print(f"[✓] Saved port distribution to {output_path}")
