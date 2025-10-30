# Thesis Project — Dynamic Port Mutation for Network Defense

## Overview
This project implements a **Moving Target Defense (MTD)** mechanism that changes the network ports of critical services to reduce exposure to port scanning and intrusion attempts.

The system continuously monitors network traffic to detect suspicious behavior and automatically mutates service ports in real time. This approach aims to increase network unpredictability and resilience against reconnaissance and exploitation.

The implementation integrates Python with the Linux networking stack through **iptables** and **NetfilterQueue**, enabling live interception and redirection of packets.

---

## 1. System Concept
Traditional systems expose services on static ports (for example, SSH on 22, HTTP on 80). This predictability allows attackers to easily locate and target services through automated scans.

This project introduces a dynamic defense mechanism that:
1. Monitors incoming TCP connection attempts.
2. Detects scanning behavior based on connection frequency and timing.
3. Triggers automatic port mutation for the targeted service.
4. Updates firewall rules to maintain legitimate access.
5. Periodically rotates service ports, even in the absence of attacks.

---

## 2. Architecture Overview

### 2.1 Detection Engine
- Uses a **sliding time window** to observe TCP SYN packets from each source IP.
- Identifies potential scanning when the number of connection attempts exceeds a defined threshold.
- Parameters:
  - `sliding_window_seconds`: duration of observation per IP.
  - `conn_threshold`: number of attempts considered suspicious.
  - `queue_num`: NetfilterQueue queue number for packet interception.
  - `dry_run`: enables safe testing without modifying iptables.

### 2.2 Mutation Engine
- Each service (e.g., web, API, database, SSH, FTP) has a range of possible ports.
- Upon detection of a scan or timeout event:
  - A new port is randomly selected from the allowed range.
  - Internal state is updated.
  - Firewall rules are modified to redirect connections from the old to the new port.
- All mutation events are logged in memory, recording timestamp, affected service, and reason.

### 2.3 Time-Driven Manager
- A background thread (`PortManager`) monitors how long each service port has been active.
- If a port exceeds its configured lifetime, it is rotated automatically.
- Default values:
  - `PORT_LIFETIME_SECONDS = 60`
  - `CHECK_INTERVAL_SECONDS = 5`

### 2.4 Firewall Integration
- A custom chain (`MTD_REDIRECT`) is created within the `nat` table.
- The script adds and removes rules in:
  - `PREROUTING` (to redirect traffic to new ports).
  - `INPUT` (to link NetfilterQueue for packet inspection).
- On shutdown, all modifications are cleaned up automatically.

---

## 3. Code Structure

| Component | Description |
|------------|--------------|
| `MTD_CONFIG` | Defines the allowed port ranges for each service type. |
| `DETECTION` | Defines detection thresholds and NFQUEUE configuration. |
| `MTDState` | Tracks service information, mutation history, and synchronization. |
| `mutate_service_port()` | Performs service port mutation and updates firewall rules. |
| `nfq_packet_callback()` | Packet handler that detects scanning behavior and triggers mutations. |
| `PortManager` | Background thread for time-based mutations. |
| `setup_iptables_chain()` / `cleanup_iptables_chain()` | Handle creation and removal of iptables rules and chains. |

---

## 4. Execution Instructions

### Requirements
- **Operating System:** Linux with iptables and Netfilter support.
- **Privileges:** Root (required for NFQUEUE and iptables).
- **Python:** Version 3.8 or higher.
- **Dependencies:**
  - `scapy`
  - `netfilterqueue`

### Running in Safe (Dry-Run) Mode
This mode simulates the behavior without modifying iptables:
```python
DETECTION["dry_run"] = True
python3 thesis.py
```

## 5. Example Behavior

### Initialization
On startup, the script initializes default ports:
```
Web Server      | Type: web       | Port: 80
Database        | Type: database  | Port: 5400
API Gateway     | Type: api       | Port: 3000
SSH Service     | Type: ssh       | Port: 22
FTP Server      | Type: ftp       | Port: 21
```

### Detection-Based Mutation
When repeated connection attempts from the same IP are detected:
```
[MUTATION] Web Server 80 -> 8090 (reason=scan_from_192.168.1.10_to_port_80)
```

### Time-Based Rotation
Even in the absence of an attack, ports are periodically changed:
```
[MANAGER] Rotating SSH Service (port 22) due to timeout
```

---