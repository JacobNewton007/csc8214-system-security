"""The PSI Server: relays key material, intersects digest lists, logs messages.

The Server holds no input set. It never sees a raw set element; everything it
does receive is kept in a message log exposed at GET /log.

    python3 psi/server.py --port 8214
"""

from __future__ import annotations

import argparse
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

CLIENTS_PER_SESSION = 2


@dataclass
class Session:
    public_keys: dict[str, int] = field(default_factory=dict)
    digests: dict[str, list[str]] = field(default_factory=dict)
    intersection: list[str] | None = None


class Store:
    """Server state, guarded by a single lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._log: list[dict[str, Any]] = []

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._log.clear()

    def log(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._log)

    def record_public_key(self, session_id: str, client_id: str, public_key: int) -> None:
        """PROTOCOL STEP 1 - store a client's Diffie-Hellman public value."""
        with self._lock:
            self._session(session_id).public_keys[client_id] = public_key
            self._append(session_id, "received", client_id, "DH_PUBLIC_KEY",
                         {"public_key_truncated": f"{str(public_key)[:32]}..."})

    def peer_public_key(self, session_id: str, client_id: str) -> tuple[str, int] | None:
        """PROTOCOL STEP 1 - hand a client the other client's public value."""
        with self._lock:
            keys = self._session(session_id).public_keys
            peer = next(((c, k) for c, k in keys.items() if c != client_id), None)
            if peer is not None:
                self._append(session_id, "sent", client_id, "DH_PEER_KEY",
                             {"peer": peer[0],
                              "public_key_truncated": f"{str(peer[1])[:32]}..."})
            return peer

    def record_digests(self, session_id: str, client_id: str, mode: str,
                       digests: list[str]) -> bool:
        """PROTOCOL STEP 3 - store one client's blinded set. Returns True if both are in.

        This log entry is the Server's entire view of the client: no raw set
        element appears in it.
        """
        with self._lock:
            session = self._session(session_id)
            if client_id in session.digests:
                raise KeyError("this client already submitted")
            session.digests[client_id] = digests
            self._append(session_id, "received", client_id, "BLINDED_SET",
                         {"mode": mode, "count": len(digests), "digests": digests})
            return len(session.digests) == CLIENTS_PER_SESSION

    def intersection(self, session_id: str) -> list[str] | None:
        """PROTOCOL STEP 4 - intersect the two digest lists, once both have arrived."""
        with self._lock:
            session = self._session(session_id)
            if len(session.digests) < CLIENTS_PER_SESSION:
                return None
            if session.intersection is None:
                first, second = session.digests.values()
                session.intersection = sorted(set(first) & set(second))
                self._append(session_id, "sent", "both clients", "INTERSECTION",
                             {"count": len(session.intersection),
                              "digests": session.intersection})
            return session.intersection

    def submitted_by(self, session_id: str) -> list[str]:
        with self._lock:
            return sorted(self._session(session_id).digests)

    def _session(self, session_id: str) -> Session:
        return self._sessions.setdefault(session_id, Session())

    def _append(self, session_id: str, direction: str, peer: str, kind: str,
                payload: dict[str, Any]) -> None:
        self._log.append({
            "seq": len(self._log) + 1,
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            "session": session_id,
            "direction": direction,
            "peer": peer,
            "message": kind,
            "payload": payload,
        })


class PSIRequestHandler(BaseHTTPRequestHandler):
    server_version = "CSC8214-PSI-Server/1.0"
    store: Store

    def log_message(self, fmt: str, *args: Any) -> None:
        """Suppress the default stderr access log."""

    def do_GET(self) -> None:
        parts = self._path_parts()

        if parts == ["health"]:
            return self._send(200, {"status": "ok"})

        if parts == ["log"]:
            return self._send(200, {"messages": self.store.log()})

        if len(parts) == 4 and parts[0] == "session" and parts[2] == "peer-key":
            peer = self.store.peer_public_key(parts[1], parts[3])
            if peer is None:
                return self._send(409, {"error": "peer key not posted yet"})
            return self._send(200, {"peer": peer[0], "public_key": str(peer[1])})

        if len(parts) == 3 and parts[0] == "session" and parts[2] == "result":
            intersection = self.store.intersection(parts[1])
            if intersection is None:
                return self._send(409, {"error": "waiting for both clients",
                                        "received_from": self.store.submitted_by(parts[1])})
            return self._send(200, {"intersection": intersection})

        self._send(404, {"error": "unknown endpoint"})

    def do_POST(self) -> None:
        parts = self._path_parts()
        try:
            body = self._body()
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid JSON"})

        if parts == ["reset"]:
            self.store.reset()
            return self._send(200, {"status": "reset"})

        if len(parts) == 3 and parts[0] == "session" and parts[2] == "key":
            client_id, public_key = body.get("client_id"), body.get("public_key")
            if not client_id or public_key is None:
                return self._send(400, {"error": "client_id and public_key required"})
            self.store.record_public_key(parts[1], client_id, int(public_key))
            return self._send(200, {"status": "stored"})

        if len(parts) == 3 and parts[0] == "session" and parts[2] == "digests":
            client_id, digests = body.get("client_id"), body.get("digests")
            if not client_id or not isinstance(digests, list):
                return self._send(400, {"error": "client_id and digests required"})
            try:
                ready = self.store.record_digests(
                    parts[1], client_id, body.get("mode", "unspecified"),
                    [str(d) for d in digests])
            except KeyError as exc:
                return self._send(409, {"error": str(exc)})
            return self._send(200, {"status": "stored", "both_clients_ready": ready})

        self._send(404, {"error": "unknown endpoint"})

    def _path_parts(self) -> list[str]:
        return [p for p in urlparse(self.path).path.split("/") if p]

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def _send(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def serve(host: str, port: int) -> None:
    handler = type("BoundHandler", (PSIRequestHandler,), {"store": Store()})
    httpd = ThreadingHTTPServer((host, port), handler)
    print(f"[server] listening on http://{host}:{port} (no input set of its own)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] shutting down", flush=True)
    finally:
        httpd.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CSC8214 PSI Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8214)
    args = parser.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
