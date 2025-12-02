import shodan
from collections import Counter
import json
import os

API_KEY = os.getenv("SHODAN_API_KEY")

api = shodan.Shodan(API_KEY)

ports = Counter()

queries = [
    
    "port:8080", "port:8081", "port:8082", "port:8083", "port:8084", #web
    "port:3001", "port:3002", "port:3003", #api
    "port:5400", "port:5401", "port:5402", #database
    "port:2200", "port:2201", "port:2202", #ssh
    "port:2100", "port:2101", "port:2102" #ftp
]

for q in queries:
    print("[+] Querying:", q)
    results = api.search(q, limit=1000)
    for r in results["matches"]:
        ports[r["port"]] += 1

with open("port_distribution.json", "w") as f:
    json.dump(ports.most_common(), f, indent=2)

print("Saved port_distribution.json")
