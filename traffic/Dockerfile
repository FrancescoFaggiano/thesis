FROM python:3.11-slim

# ---------------- System dependencies ----------------
# - nmap: needed for scanner & malware
# - iproute2: useful for debugging / networking
# - ca-certificates: TLS sanity
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---------------- Working directory ----------------
WORKDIR /app

# ---------------- Copy traffic code ----------------
# We copy the whole traffic folder so paths stay consistent:
#   /app/traffic/legitimate/legit_pool.py
#   /app/traffic/scanner/scanner_pool.py
#   /app/traffic/malware/malware_pool.py
COPY . /app/traffic

# ---------------- Default command ----------------
# Overridden by docker-compose `command:` for each pool
CMD ["python", "traffic/legitimate/legit_pool.py"]
