import json, random

with open("port_distribution.json") as f:
    ports = json.load(f)

port_list = []
for p, w in ports:
    port_list.extend([p] * w)

def generate_scan_sequence(n=1000):
    return random.sample(port_list, min(n,len(port_list)))

sequence = generate_scan_sequence(200)

with open("synthetic_ports.json","w") as f:
    json.dump(sequence,f)

print("Saved synthetic_ports.json")
