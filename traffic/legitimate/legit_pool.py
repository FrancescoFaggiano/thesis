# traffic/legitimate/legit_pool.py
import json, time, random
import http.client
from pathlib import Path
import os

STATE_FILE = Path(os.environ.get("STATE_FILE", "/app/shared/state.json"))


TARGET_HOST = "localhost"
SERVICE_ID = "svc-web"

REQUEST_EVERY = 0.5
TIMEOUT = 2.0

FAILURES_BEFORE_REFRESH = 5
REFRESH_COOLDOWN = 3.0

# optional realism knob: reconnect occasionally (won't hit 8 SYN / 10s)
RECONNECT_EVERY = (30, 60)  # seconds (min, max)

def read_port():
    data = json.loads(STATE_FILE.read_text())
    for svc in data.get("services", []):
        if svc.get("id") == SERVICE_ID:
            return int(svc["current_port"])
    raise RuntimeError("svc-web not found")

def make_conn(port: int):
    return http.client.HTTPConnection(TARGET_HOST, port, timeout=TIMEOUT)

def http_get(conn: http.client.HTTPConnection) -> bool:
    try:
        conn.request("GET", "/")
        r = conn.getresponse()
        r.read()
        return 200 <= r.status < 400
    except Exception:
        return False

def main():
    port = read_port()
    conn = make_conn(port)
    print(f"[LEGIT] start on port {port}")

    ok = fail = 0
    consecutive_failures = 0
    last_refresh = 0.0

    next_reconnect = time.time() + random.uniform(*RECONNECT_EVERY)

    while True:
        # occasional reconnect (realistic)
        if time.time() >= next_reconnect:
            try:
                conn.close()
            except Exception:
                pass
            conn = make_conn(port)
            next_reconnect = time.time() + random.uniform(*RECONNECT_EVERY)

        success = http_get(conn)

        if success:
            ok += 1
            consecutive_failures = 0
        else:
            fail += 1
            consecutive_failures += 1

            # reset TCP connection on failure
            try:
                conn.close()
            except Exception:
                pass
            conn = make_conn(port)

            # only AFTER repeated failures does the client re-discover port
            if consecutive_failures >= FAILURES_BEFORE_REFRESH:
                now = time.time()
                if now - last_refresh >= REFRESH_COOLDOWN:
                    try:
                        new_port = read_port()
                        if new_port != port:
                            print(f"[LEGIT] rediscovered port {new_port}")
                            port = new_port
                            # IMPORTANT: rebuild connection to the new port immediately
                            try:
                                conn.close()
                            except Exception:
                                pass
                            conn = make_conn(port)
                        last_refresh = now
                        consecutive_failures = 0
                    except Exception as e:
                        print(f"[LEGIT] refresh failed: {e}")

        if (ok + fail) % 50 == 0:
            total = ok + fail
            print(f"[LEGIT] port={port} ok={ok} fail={fail} fail_rate={fail/total:.3f}")

        time.sleep(REQUEST_EVERY)

if __name__ == "__main__":
    main()
