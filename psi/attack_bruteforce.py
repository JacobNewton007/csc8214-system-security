"""Question A.5: the Server tries to invert the digests it legitimately received.

Against the unkeyed protocol of A.3 this succeeds, because the hash function is
public and deterministic and the element domain is tiny. Against the keyed
variant it fails, because the Server holds no key.

    python3 psi/attack_bruteforce.py --session run1 --id-prefix 2604
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from collections.abc import Iterable
from typing import Any

from common import Element, digest

DEFAULT_SERVER = "http://127.0.0.1:8214"
SMALL_INTEGER_RANGE = 10_000
STUDENT_NUMBER_DIGITS = 9


def fetch_log(server: str) -> list[dict[str, Any]]:
    with urllib.request.urlopen(f"{server}/log", timeout=10) as response:
        return json.loads(response.read())["messages"]


def harvest(log: list[dict[str, Any]], session: str) -> tuple[dict[str, list[str]], str]:
    """Everything the Server holds for one session, and the mode used."""
    digests: dict[str, list[str]] = {}
    mode = "unknown"
    for message in log:
        if message["session"] == session and message["message"] == "BLINDED_SET":
            digests[message["peer"]] = message["payload"]["digests"]
            mode = message["payload"].get("mode", "unknown")
    return digests, mode


def brute_force(targets: set[str], candidates: Iterable[Element]
                ) -> tuple[dict[str, Element], int]:
    """Hash candidates until every target digest is matched."""
    recovered: dict[str, Element] = {}
    tried = 0
    for candidate in candidates:
        tried += 1
        found = digest(candidate)
        if found in targets:
            recovered[found] = candidate
            if len(recovered) == len(targets):
                break
    return recovered, tried


def report_keyed_failure() -> None:
    print("  The digests are HMAC-SHA256 under a key agreed between the two")
    print("  clients by Diffie-Hellman. The Server relayed the public values")
    print("  g^a and g^b but cannot compute g^ab, so it has no key.")
    print("  => the Server cannot compute the digest of ANY candidate value.")
    print("  => 0 of the elements can be recovered by hashing candidates.")
    print()
    print("  RESULT: attack fails.")


def main() -> None:
    parser = argparse.ArgumentParser(description="A.5 brute-force attack by the Server")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--session", default="run1")
    parser.add_argument("--small-range", type=int, default=SMALL_INTEGER_RANGE)
    parser.add_argument("--id-prefix", default=None,
                        help="student-number prefix the Server is assumed to know")
    parser.add_argument("--id-width", type=int, default=5,
                        help="number of unknown digits after the prefix")
    args = parser.parse_args()

    harvested, mode = harvest(fetch_log(args.server), args.session)
    if not harvested:
        raise SystemExit(f"no BLINDED_SET messages logged for session {args.session!r}")

    print("=" * 74)
    print(f"A.5  SERVER-SIDE BRUTE-FORCE ATTACK ON SESSION {args.session!r}")
    print("=" * 74)
    for client, digests in sorted(harvested.items()):
        print(f"  Server holds {len(digests)} digests from {client}")
    print(f"  Blinding mode used by the clients: {mode}")
    print()

    if mode == "hmac":
        return report_keyed_failure()

    targets = {d for digests in harvested.values() for d in digests}

    print(f"  Phase 1: hash every integer in [0, {args.small_range}) and compare.")
    started = time.perf_counter()
    recovered, tried = brute_force(targets, range(args.small_range))
    elapsed = time.perf_counter() - started
    rate = tried / max(elapsed, 1e-9)
    print(f"           {tried:,} candidates hashed in {elapsed:.2f}s "
          f"({rate:,.0f} hashes/second, single-threaded Python)")
    print()

    for client, digests in sorted(harvested.items()):
        found = {d: recovered[d] for d in digests if d in recovered}
        print(f"  {client}: recovered {len(found)}/{len(digests)} elements")
        for element_digest, value in sorted(
                found.items(), key=lambda item: (isinstance(item[1], str), item[1])):
            print(f"      {element_digest[:24]}...  ->  {value}")
        for element_digest in (d for d in digests if d not in recovered):
            print(f"      {element_digest[:24]}...  ->  NOT FOUND in this range")
    print()

    remaining = targets - set(recovered)
    if remaining:
        print(f"  Phase 2: {len(remaining)} digest(s) survived phase 1. These are")
        print("           consistent with a student number. A student number is")
        print("           NOT secret and follows a published format, so the")
        print("           Server can search that domain too.")
        if args.id_prefix is not None:
            space = 10 ** args.id_width
            prefix, width = args.id_prefix, args.id_width
            print(f"           Searching {prefix}{'0' * width}..{prefix}{'9' * width} "
                  f"({space:,} candidates).")
            # Candidates are generated as strings so that a student number with
            # a letter prefix is covered as easily as a purely numeric one.
            started = time.perf_counter()
            found, tried = brute_force(
                remaining, (f"{prefix}{i:0{width}d}" for i in range(space)))
            elapsed = time.perf_counter() - started
            print(f"           {tried:,} candidates hashed in {elapsed:.2f}s")
            for element_digest, value in found.items():
                print(f"      {element_digest[:24]}...  ->  {value}"
                      "   <-- STUDENT NUMBER RECOVERED")
            recovered.update(found)
            remaining = targets - set(recovered)
        full_space = 10 ** STUDENT_NUMBER_DIGITS
        print("           Even with no hint at all, the whole 9-digit space is")
        print(f"           {full_space:,} candidates: about "
              f"{full_space / rate / 3600:.1f} hours in this unoptimised Python,")
        print("           and seconds on a GPU. The domain, not the hash, is the")
        print("           weakness.")
    print()
    print(f"  RESULT: {len(recovered)}/{len(targets)} distinct digests inverted.")
    if remaining:
        print(f"          {len(remaining)} digest(s) still unknown "
              "(outside the ranges searched here).")


if __name__ == "__main__":
    main()
