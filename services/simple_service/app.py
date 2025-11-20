from flask import Flask, jsonify
from prometheus_client import generate_latest, CollectorRegistry, CONTENT_TYPE_LATEST, Counter
import os

app = Flask(__name__)
hits = Counter("service_hits_total", "Number of hits to the service", ["service"])

SERVICE_NAME = os.environ.get("SERVICE_NAME", "simple_service")

@app.route("/")
def index():
    hits.labels(service=SERVICE_NAME).inc()
    return f"<html><body><h1>{SERVICE_NAME}</h1></body></html>"

@app.route("/health")
def health():
    return jsonify({"status":"ok", "service": SERVICE_NAME})

@app.route("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
