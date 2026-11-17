"""
CSC8214 System Security - Assignment Part A (Private Set Intersection)

THE CLIENT. The same program is run twice, once as "client1" and once as
"client2". Each client holds its own private set and learns the intersection
without ever sending a raw set element to the Server.

Protocol steps implemented here (the comments PROTOCOL STEP n map onto the
steps of the protocol described in Question A.3 of the report):

  STEP 1  (hmac mode only) agree a MAC key with the *other client* by
          Diffie-Hellman, relayed by - but opaque to - the Server.
  STEP 2  blind every element of the local set with the hash function, and
          keep a private lookup table {digest: element}.
  STEP 3  send the shuffled list of digests to the Server.
  STEP 4  the Server intersects the two digest lists (see server.py).
  STEP 5  download the intersecting digests and invert them through the local
          lookup table to recover the actual intersecting elements.

Example:
  python3 psi/client.py --client-id client1 --set 1,2,5,9,123456789
"""

from __future__ import annotations

import argparse
import json
import random
import time
import urllib.error
import urllib.request

from common import blind_set, dh_keypair, dh_shared_key

DEFAULT_SERVER = "http://127.0.0.1:8214"


# ---------------------------------------------------------------------------
# Tiny HTTP helpers (standard library only - no third-party dependencies).
# ---------------------------------------------------------------------------

def _post(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get(url: str) -> tuple[int, dict]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _poll(url: str, label: str, attempts: int = 100, delay: float = 0.1) -> dict:
    """Poll an endpoint that only becomes available once the peer has acted."""
    for _ in range(attempts):
        status, body = _get(url)
        if status == 200:
            return body
        time.sleep(delay)
    raise TimeoutError(f"timed out waiting for {label}")


# ---------------------------------------------------------------------------
# The protocol
# ---------------------------------------------------------------------------

def run_client(client_id: str, elements: list, mode: str, session: str,
               server: str = DEFAULT_SERVER, verbose: bool = True) -> dict:
    def say(msg: str) -> None:
        if verbose:
            print(f"[{client_id}] {msg}", flush=True)

    say(f"private set = {sorted(map(str, elements))}  (never leaves this process)")

    # ---- PROTOCOL STEP 1: key agreement between the two clients ------------
    key = None
    if mode == "hmac":
        private, public = dh_keypair()
        _post(f"{server}/session/{session}/key",
              {"client_id": client_id, "public_key": str(public)})
        say("sent my Diffie-Hellman public value to the Server for relay")
        peer = _poll(f"{server}/session/{session}/peer-key/{client_id}", "peer DH key")
        key = dh_shared_key(private, int(peer["public_key"]))
        say(f"derived shared MAC key with {peer['peer']} "
            f"(first 8 bytes: {key[:8].hex()}) - the Server cannot derive this")

    # ---- PROTOCOL STEP 2: blind the local set ------------------------------
    # lookup_table maps digest -> element. It is the client's private state and
    # is the only thing that can invert a digest back to an element.
    lookup_table = blind_set(elements, key)
    say(f"blinded {len(lookup_table)} elements with "
        f"{'HMAC-SHA256 (keyed)' if key else 'SHA-256 (unkeyed)'}")
    for dgst, element in lookup_table.items():
        say(f"    {element!s:>12}  ->  {dgst}")

    # ---- PROTOCOL STEP 3: send the SHUFFLED digests to the Server ----------
    # Shuffling matters: if the digests were sent in the original set order, the
    # position of a digest would leak the ordering of the underlying elements.
    outgoing = list(lookup_table.keys())
    random.shuffle(outgoing)
    _post(f"{server}/session/{session}/digests",
          {"client_id": client_id, "mode": mode, "digests": outgoing})
    say(f"sent {len(outgoing)} shuffled digests to the Server (no raw elements sent)")

    # ---- PROTOCOL STEP 4 happens on the Server -----------------------------
    # ---- PROTOCOL STEP 5: fetch the result and invert it locally -----------
    result = _poll(f"{server}/session/{session}/result", "intersection")
    intersecting_digests = result["intersection"]
    say(f"Server returned {len(intersecting_digests)} intersecting digest(s)")

    # Only this client can map those digests back to elements, because only this
    # client holds the lookup table. The Server never performs this step.
    intersection = sorted(
        (lookup_table[d] for d in intersecting_digests if d in lookup_table),
        key=lambda v: (isinstance(v, str), v),
    )
    say(f"INTERSECTION = {intersection}")

    return {
        "client_id": client_id,
        "mode": mode,
        "input_set": list(elements),
        "digests_sent": outgoing,
        "lookup_table": {d: str(e) for d, e in lookup_table.items()},
        "intersection_digests": intersecting_digests,
        "intersection": intersection,
    }


def _parse_set(raw: str) -> list:
    """Parse "1,2,5,9,ID" into a list, keeping integers as integers."""
    items = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        items.append(int(token) if token.lstrip("-").isdigit() else token)
    return items


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSC8214 PSI Client")
    parser.add_argument("--client-id", required=True, choices=["client1", "client2"])
    parser.add_argument("--set", required=True, help="comma-separated set elements")
    parser.add_argument("--mode", default="plain", choices=["plain", "hmac"])
    parser.add_argument("--session", default="run1")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    args = parser.parse_args()

    run_client(args.client_id, _parse_set(args.set), args.mode, args.session, args.server)
