# Moving Target Defense (MTD) Port Mutation System

## Overview

This project implements a **Moving Target Defense (MTD)** system that dynamically rotates the network ports of decoy services to disrupt attacker reconnaissance while maintaining uninterrupted service for legitimate users.

It achieves this through:

- Real packet-level monitoring using **Scapy + NetfilterQueue**
- **iptables REDIRECT** rules to preserve legitimate traffic
- Dynamic decoy service deployment using **Docker**
- Shared state coordination between MTD components
- Detailed logging for experimental analysis
- **Prometheus** metrics and **Grafana** dashboards

---

## Architecture Overview

The system uses a hybrid architecture:

- **mtd-detector** runs with host networking and elevated privileges  
- All other components (mutator, controller, services) run inside Docker  
- A shared directory coordinates state, logs, and triggers  
- Prometheus scrapes all metrics  
- Grafana visualizes trends and anomalies

```
                    Clients / Attackers
                           │
                           ▼
                 ┌──────────────────────┐
                 │ Kali Linux Host VM  │
                 │  (iptables layer)   │
                 └───────┬─────────────┘
                         │ NFQUEUE
                         ▼
        ┌─────────────────────────────────────────┐
        │         mtd-detector (Docker)           │
        │  • Scapy + NetfilterQueue packet capture│
        │  • Detects scans                        │
        │  • Logs all connections                 │
        │  • Adds iptables REDIRECT & DROP rules  │
        │  • Generates triggers for the mutator   │
        │  • Exposes Prometheus metrics           │
        └─────────────────┬───────────────────────┘
                          │ Shared Volume
                          ▼
          ┌────────────────────────────────────┐
          │               Docker                │
          │   ┌──────────────┐   ┌────────────┐│
          │   │ mtd-mutator  │   │ controller ││
          │   │ - selects    │   │ - launches ││
          │   │   new ports  │   │   decoys   ││
          │   └──────────────┘   └────────────┘│
          │            │   updates state         │
          │            ▼                          │
          │     shared/state.json                 │
          │                                        │
          │   ┌──────────────┐    ┌───────────┐   │
          │   │ decoy svc #1 │    │ svc #N    │   │
          │   └──────────────┘    └───────────┘   │
          │                                        │
          │      Prometheus <──── metrics ───►     │
          │      Grafana     ◄── dashboards ───    │
          └────────────────────────────────────────┘
```

## Execution Instructions

Start the entire system:

```bash
sudo docker compose up --build
```

URLs:

|    Component    | URL |
|-----------------|-----|
| Prometheus      | http://localhost:9090 |
| Grafana         | http://localhost:3000 |
| Decoy Services  | Port defined in state.json |

---

## Testing Scanning Behavior

Perform an nmap scan:

```bash
sudo nmap -p 1-10000 localhost
```

Expected results:

1. Detector logs SYN packets  
2. Scan detection triggers mutation  
3. Mutator updates `state.json`  
4. Controller rotates the service container  
5. Detector installs `iptables REDIRECT`  
6. Metrics update in Prometheus  
7. Dashboards update in Grafana  

---

## Legitimate Traffic Behavior

Even after a port mutation (e.g., 8080 → 5401), detector installs:

```
iptables -t nat -A MTD_REDIRECT   -p tcp --dport 8080   -j REDIRECT --to-ports 5401
```

This ensures:

- Legitimate users connecting to old ports still reach the service  
- Zero downtime  
- Transparent redirection  
- Attackers receive inconsistent data

Test continuity:

```bash
while true; do
    curl -s http://localhost:8080 | grep Web
    sleep 1
done
```

---

## How iptables REDIRECT Works

Detector compares old/new ports and installs:

```
iptables -t nat -A MTD_REDIRECT     -p tcp --dport <old_port>     -j REDIRECT --to-ports <new_port>
```

This preserves connections while disrupting attacker reconnaissance.

---

## Logging Structure

All logs appear under:

```
shared/logs/
```

### `traffic.log`
Contains:
- All TCP SYN packets
- Scan detections
- REDIRECT/DROP rules installed

### `mutations.log`
Tracks:
- Every port mutation
- Reason (time-based vs scan-triggered)

### `mutations_controller.csv`
Tracks:
- Container restarts
- Observed port changes

---

## Grafana Dashboards

Grafana visualizes:

- Mutation timeline  
- Scan detection rates  
- Redirect rules  
- Legitimate traffic continuity  
- Service hit frequency  
- Suspicious IP activity  

This satisfies the requirement:

> “Prometheus aggregates metrics; Grafana identifies patterns, trends, anomalies.”

---

## Conclusion

This system provides:

- Real packet-level detection  
- Dynamic port mutation  
- Connectivity-preserving MTD using iptables  
- Modular Docker-managed components  
- Complete experiment logging  
- Prometheus-based monitoring  
- Grafana visualization  

It is fully suitable for academic experimentation and thesis research.
