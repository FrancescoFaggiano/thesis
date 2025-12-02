FROM python:3.11-slim

RUN apt update && apt install -y nmap curl
RUN pip install shodan

WORKDIR /app

COPY attacker.py .
COPY attack_profile.json .

CMD ["python", "attacker.py"]

FROM python:3.11-slim

RUN apt update && \
    apt install -y nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY attacker.py .
COPY attack_profile.json .

CMD ["python", "attacker.py"]
