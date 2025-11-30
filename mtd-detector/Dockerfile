FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y \
      iptables \
      libnetfilter-queue-dev \
      gcc \
      libffi-dev \
      && pip install --no-cache-dir -r requirements.txt \
      && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY detector.py .

CMD ["python", "detector.py"]
