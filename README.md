# Moving Target Defense (MTD) — Port Mutation Testbed

This repository implements the thesis testbed for a **Moving Target Defense (MTD)** mechanism that **rotates service ports** to disrupt reconnaissance, while preserving availability for benign clients.

The system is orchestrated with **Docker Compose** and includes:
- Packet-level **detection** using **iptables + NetfilterQueue + Scapy**
- A **mutator** that rotates ports (time-based and scan-triggered)
- A **controller** that (re)creates service containers based on `shared/state.json`
- Traffic generators: **legitimate**, **scanner**, and **malware-like** pools
- **Prometheus** scraping `/metrics` endpoints for monitoring

> **Important:** the detector manipulates host iptables and uses NFQUEUE. Run this only in a controlled environment (VM/lab).

---

## Repository layout

- `docker-compose.yml` — brings up the whole testbed
- `mtd-detector/` — detection + iptables/NFQUEUE logic (privileged, host network)
- `mtd-mutator/` — port rotation + trigger processing
- `mtd-controller/` — container orchestration via Docker socket
- `services/simple_service/` — template service image (Flask) used for decoys
- `traffic/` — traffic pools (legitimate / scanner / malware)
- `shared/` — shared artifacts mounted into containers (`state.json`, `logs/`, `triggers/`)
- `monitoring/prometheus/` — Prometheus scrape configuration
- `shodan/` — optional scripts to build Shodan-driven port distributions for traffic pools

---

## How it works (high level)

1. **Controller** reads `shared/state.json` and ensures there is **one container per service** with host port mapping to the `current_port`.
2. **Detector** installs iptables rules:
   - an `MTD_REDIRECT` chain (NAT) for old→new port forwarding
   - NFQUEUE rules for **NEW** TCP connections (INPUT/OUTPUT)
   It inspects SYN packets with NFQUEUE+Scapy, logs events, and may write scan triggers into `shared/triggers/`.
3. **Mutator**:
   - periodically rotates ports (`time_rotation`)
   - rotates immediately on scan triggers (`scan_from_<src>_to_<dst>`)
   It updates `shared/state.json` and logs mutations.
4. **Prometheus** scrapes `/metrics` from detector and controller (mutator exposes `/metrics` too, but is not scraped by default in the provided config).

---

## Quick start

### Prerequisites
- Linux host/VM with iptables and NFQUEUE support
- Docker + Docker Compose v2
- Run with permissions that allow iptables changes (typically `sudo`)

### 1) Create Shodan-driven port lists (required for scanner/malware pools)

The scanner and malware pools expect these files:
- `traffic/data/scanner_ports.json`
- `traffic/data/malware_ports.json`

Generate them with Shodan (recommended):

1. Create `shodan/.env`:
   ```bash
   SHODAN_API_KEY=your_key_here
   ```
2. From repo root:
   ```bash
   python3 shodan/shodan_ports.py
   python3 shodan/build_scanner_ports.py
   python3 shodan/build_malware_ports.py
   ```

**No Shodan key?** You can create minimal files manually.  
Format is a JSON list of `[port, weight]` pairs, e.g.:
```json
[
  [80, 1000],
  [443, 900],
  [22, 700],
  [8080, 500]
]
```

### 2) Start everything

From repo root:
```bash
sudo docker compose up --build
```

### 3) Verify it’s running
- Prometheus: `http://localhost:9090`
- Detector metrics: `http://localhost:9101/metrics`
- Controller metrics: `http://localhost:9100/metrics`
- Mutator metrics (exposed): `http://localhost:9102/metrics`

The active service ports are listed in:
- `shared/state.json`

---

## Configuration knobs (via `docker-compose.yml`)

### Detector (`detector`)
- `METRICS_PORT` (default `9101`)
- `QUEUE_NUM` (default `1`)
- `SLIDING_WINDOW_SECONDS` (default `10`)
- `CONN_THRESHOLD` (default `8`)
- `TRIGGER_COOLDOWN_SECONDS` (default `5`)
- `REDIRECT_GRACE_SECONDS` (default `30`)

### Mutator (`mutator`)
- `METRICS_PORT` (default `9102`)
- `PORT_LIFETIME_SECONDS` (default `60`)
- `CHECK_INTERVAL` (default `5`)

### Controller (`controller`)
- `METRICS_PORT` (default `9100`)
- `SERVICE_IMAGE` (default `mtd_simple_service:latest`)

---

## Logging & shared artifacts

All components write into the shared volume mounted at `/app/shared`:

- `shared/state.json` — authoritative current ports per service
- `shared/logs/traffic.log` — detector events (connections, scans, redirects, drops)
- `shared/logs/mutations.log` — mutator decisions (old→new, reason)
- `shared/logs/mutations_controller.csv` — controller-observed state changes / restarts
- `shared/triggers/scan_*.json` — scan triggers produced by detector and consumed by mutator

---

## Triggering a mutation (manual test)

A simple way to exceed the scan threshold is to send multiple SYNs to a service port quickly, for example using `hping3` from another host:

```bash
sudo hping3 <TARGET_IP> -p 8080 -S -c 10
```

Expected pipeline:
1. Detector logs SYNs and declares a scan when threshold is exceeded
2. Detector writes a trigger JSON in `shared/triggers/`
3. Mutator rotates the corresponding service port and updates `shared/state.json`
4. Controller restarts/remaps the service container to the new port
5. Detector installs an old→new REDIRECT rule for a grace period

---

## Prometheus

Prometheus is configured in `monitoring/prometheus/prometheus.yml` to scrape:
- `localhost:9100` (controller)
- `localhost:9101` (detector)

If you want Prometheus to scrape the mutator as well, add a target:
```yaml
  - job_name: "mtd-mutator"
    static_configs:
      - targets: ["localhost:9102"]
```

---

## Stopping the testbed

```bash
sudo docker compose down
```

---

## Notes & safety

- The detector installs iptables rules and NFQUEUE hooks. If you stop the stack abruptly, you may want to clear custom rules/chains.
- Recommended usage is inside a VM/sandbox where you can revert snapshots easily.

---

## License / attribution

This code accompanies a thesis project. If you reuse it, please cite appropriately.
