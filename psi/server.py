"""
CSC8214 System Security - Assignment Part A (Private Set Intersection)

THE SERVER.

The Server has no input set of its own. Its only jobs are:

  * PROTOCOL STEP 1 (hmac mode only): relay the two clients' Diffie-Hellman
    public values. It forwards g^a and g^b but cannot compute g^ab.
  * PROTOCOL STEP 3: receive one shuffled list of digests from each client.
  * PROTOCOL STEP 4: compute the intersection of the two digest lists and
    return it to both clients.

The Server never sees a raw set element. Everything it does receive is written
to a message log (GET /log), which is what Question A.4(i) asks to be reported
and what Question A.5 analyses.

Run with:   python3 psi/server.py --port 8214
"""

from __future__ import annotations

import argparse
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Server state. The Server is deliberately "honest but curious": it keeps
# everything it is sent so that the privacy analysis in A.5 can be done on real
# data rather than on an assumption about what it might have stored.
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_sessions: dict[str, dict] = {}
_message_log: list[dict] = []


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]


def _session(session_id: str) -> dict:
    """Fetch (creating if needed) the state for one PSI session."""
    if session_id not in _sessions:
        _sessions[session_id] = {
            "dh": {},        # client_id -> DH public value
            "digests": {},   # client_id -> list of hex digests
            "intersection": None,
        }
    return _sessions[session_id]


def _log(session_id: str, direction: str, sender: str, kind: str, payload: dict) -> None:
    """Record one message exactly as the Server saw it."""
    _message_log.append(
        {
            "seq": len(_message_log) + 1,
            "time": _now(),
            "session": session_id,
            "direction": direction,   # "received" or "sent"
            "peer": sender,
            "message": kind,
            "payload": payload,
        }
    )


class PSIRequestHandler(BaseHTTPRequestHandler):
    server_version = "CSC8214-PSI-Server/1.0"

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):  # silence the default stderr access log
        pass

    def _send_json(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    # -- routes ------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")
        parts = [p for p in path.split("/") if p]

        if path == "/health":
            return self._send_json(200, {"status": "ok"})

        # GET /log  -> everything the Server has received and sent.
        if path == "/log":
            with _lock:
                return self._send_json(200, {"messages": list(_message_log)})

        # GET /session/<id>/peer-key/<client_id>  (PROTOCOL STEP 1, hmac mode)
        if len(parts) == 4 and parts[0] == "session" and parts[2] == "peer-key":
            session_id, client_id = parts[1], parts[3]
            with _lock:
                state = _session(session_id)
                peers = {c: k for c, k in state["dh"].items() if c != client_id}
                if not peers:
                    return self._send_json(409, {"error": "peer key not posted yet"})
                peer_id, peer_key = next(iter(peers.items()))
                _log(session_id, "sent", client_id, "DH_PEER_KEY",
                     {"peer": peer_id, "public_key_truncated": str(peer_key)[:32] + "..."})
            return self._send_json(200, {"peer": peer_id, "public_key": str(peer_key)})

        # GET /session/<id>/result  (PROTOCOL STEP 4, the Server's answer)
        if len(parts) == 3 and parts[0] == "session" and parts[2] == "result":
            session_id = parts[1]
            with _lock:
                state = _session(session_id)
                if len(state["digests"]) < 2:
                    have = sorted(state["digests"])
                    return self._send_json(409, {"error": "waiting for both clients",
                                                 "received_from": have})
                if state["intersection"] is None:
                    # ---- PROTOCOL STEP 4: intersect the two digest lists ----
                    (_, d1), (_, d2) = sorted(state["digests"].items())
                    state["intersection"] = sorted(set(d1) & set(d2))
                    _log(session_id, "sent", "both clients", "INTERSECTION",
                         {"count": len(state["intersection"]),
                          "digests": state["intersection"]})
                return self._send_json(200, {"intersection": state["intersection"]})

        return self._send_json(404, {"error": "unknown endpoint"})

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        parts = [p for p in path.split("/") if p]

        try:
            body = self._read_json()
        except json.JSONDecodeError:
            return self._send_json(400, {"error": "invalid JSON"})

        if path == "/reset":  # test helper: clear all state between runs
            with _lock:
                _sessions.clear()
                _message_log.clear()
            return self._send_json(200, {"status": "reset"})

        # POST /session/<id>/key  (PROTOCOL STEP 1, hmac mode)
        if len(parts) == 3 and parts[0] == "session" and parts[2] == "key":
            session_id = parts[1]
            client_id = body.get("client_id")
            public_key = body.get("public_key")
            if not client_id or public_key is None:
                return self._send_json(400, {"error": "client_id and public_key required"})
            with _lock:
                _session(session_id)["dh"][client_id] = int(public_key)
                # The Server logs the public value. It is of no use to it: it
                # cannot derive the shared key from g^a and g^b.
                _log(session_id, "received", client_id, "DH_PUBLIC_KEY",
                     {"public_key_truncated": str(public_key)[:32] + "..."})
            return self._send_json(200, {"status": "stored"})

        # POST /session/<id>/digests  (PROTOCOL STEP 3, the main message)
        if len(parts) == 3 and parts[0] == "session" and parts[2] == "digests":
            session_id = parts[1]
            client_id = body.get("client_id")
            digests = body.get("digests")
            if not client_id or not isinstance(digests, list):
                return self._send_json(400, {"error": "client_id and digests required"})
            with _lock:
                state = _session(session_id)
                if client_id in state["digests"]:
                    return self._send_json(409, {"error": "this client already submitted"})
                state["digests"][client_id] = [str(d) for d in digests]
                # THIS LOG LINE IS THE WHOLE OF THE SERVER'S VIEW OF THE CLIENT.
                # No raw set elements appear anywhere in it.
                _log(session_id, "received", client_id, "BLINDED_SET",
                     {"mode": body.get("mode", "unspecified"),
                      "count": len(digests),
                      "digests": [str(d) for d in digests]})
                ready = len(state["digests"]) == 2
            return self._send_json(200, {"status": "stored", "both_clients_ready": ready})

        return self._send_json(404, {"error": "unknown endpoint"})


def serve(host: str, port: int) -> None:
    httpd = ThreadingHTTPServer((host, port), PSIRequestHandler)
    print(f"[server] CSC8214 PSI Server listening on http://{host}:{port}", flush=True)
    print("[server] The Server holds no input set of its own.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] shutting down", flush=True)
    finally:
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSC8214 PSI Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8214)
    args = parser.parse_args()
    serve(args.host, args.port)
