"""The PSI Client. Run once as client1 and once as client2.

    python3 psi/client.py --client-id client1 --set 1,2,5,9,260452597

Protocol steps, numbered as in Question A.3 of the report:

    STEP 0  agree a MAC key with the other client (keyed variant only)
    STEP 1  blind the local set, keeping a private {digest: element} table
    STEP 2  send the shuffled digests to the Server
    STEP 3  the Server intersects the two digest lists
    STEP 4  invert the returned digests through the local table
"""

from __future__ import annotations

import argparse
import json
import random
import time
import urllib.error
import urllib.request
from typing import Any

from common import Element, blind_set, dh_keypair, dh_shared_key

DEFAULT_SERVER = "http://127.0.0.1:8214"
POLL_ATTEMPTS = 100
POLL_DELAY_SECONDS = 0.1


def _post(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _get(url: str) -> tuple[int, dict[str, Any]]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _poll(url: str, label: str) -> dict[str, Any]:
    """Wait for an endpoint that only answers once the peer has acted."""
    for _ in range(POLL_ATTEMPTS):
        status, body = _get(url)
        if status == 200:
            return body
        time.sleep(POLL_DELAY_SECONDS)
    raise TimeoutError(f"timed out waiting for {label}")


def parse_set(raw: str) -> list[Element]:
    """Parse "1,2,5,9,ID" into a list, keeping numeric elements as integers."""
    elements: list[Element] = []
    for token in (t.strip() for t in raw.split(",")):
        if token:
            elements.append(int(token) if token.lstrip("-").isdigit() else token)
    return elements


def run_client(client_id: str, elements: list[Element], mode: str, session: str,
               server: str = DEFAULT_SERVER, verbose: bool = True) -> dict[str, Any]:
    def say(message: str) -> None:
        if verbose:
            print(f"[{client_id}] {message}", flush=True)

    say(f"private set = {sorted(map(str, elements))}  (never leaves this process)")

    # PROTOCOL STEP 0: Diffie-Hellman with the other client, relayed by the Server.
    # Used only by the improved (keyed) variant of A.5; the protocol of A.3
    # starts at Step 1.
    key: bytes | None = None
    if mode == "hmac":
        private, public = dh_keypair()
        _post(f"{server}/session/{session}/key",
              {"client_id": client_id, "public_key": str(public)})
        say("sent my Diffie-Hellman public value to the Server for relay")
        peer = _poll(f"{server}/session/{session}/peer-key/{client_id}", "peer DH key")
        key = dh_shared_key(private, int(peer["public_key"]))
        say(f"derived shared MAC key with {peer['peer']} "
            f"(first 8 bytes: {key[:8].hex()}) - the Server cannot derive this")

    # PROTOCOL STEP 1: blind locally. The table is what inverts the Server's answer.
    table = blind_set(elements, key)
    say(f"blinded {len(table)} elements with "
        f"{'HMAC-SHA256 (keyed)' if key else 'SHA-256 (unkeyed)'}")
    for element_digest, element in table.items():
        say(f"    {element!s:>12}  ->  {element_digest}")

    # PROTOCOL STEP 2: send shuffled, so position cannot leak the ordering of the set.
    outgoing = list(table)
    random.shuffle(outgoing)
    _post(f"{server}/session/{session}/digests",
          {"client_id": client_id, "mode": mode, "digests": outgoing})
    say(f"sent {len(outgoing)} shuffled digests to the Server (no raw elements sent)")

    # PROTOCOL STEP 3 happens on the Server.
    # PROTOCOL STEP 4: only this client holds the table, so only it can invert the result.
    returned = _poll(f"{server}/session/{session}/result", "intersection")["intersection"]
    say(f"Server returned {len(returned)} intersecting digest(s)")
    intersection = sorted((table[d] for d in returned if d in table),
                          key=lambda value: (isinstance(value, str), value))
    say(f"INTERSECTION = {intersection}")

    return {
        "client_id": client_id,
        "mode": mode,
        "input_set": list(elements),
        "digests_sent": outgoing,
        "lookup_table": {d: str(e) for d, e in table.items()},
        "intersection_digests": returned,
        "intersection": intersection,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="CSC8214 PSI Client")
    parser.add_argument("--client-id", required=True, choices=["client1", "client2"])
    parser.add_argument("--set", required=True, help="comma-separated set elements")
    parser.add_argument("--mode", default="plain", choices=["plain", "hmac"])
    parser.add_argument("--session", default="run1")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    args = parser.parse_args()

    run_client(args.client_id, parse_set(args.set), args.mode, args.session, args.server)


if __name__ == "__main__":
    main()
