FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required for NFQUEUE, iptables, Scapy, debugging
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    procps \
    net-tools \
    iputils-ping \
    tcpdump \
    libnetfilter-queue-dev \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY detector.py .

# Run Python unbuffered so logs appear immediately
CMD ["python", "-u", "detector.py"]
