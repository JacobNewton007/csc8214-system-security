"""
CSC8214 System Security - Assignment Question A.5 (privacy analysis).

THE SERVER AS AN ATTACKER.

This script plays the role of the honest-but-curious Server. It takes *only*
the data the Server legitimately received during a run (the two lists of
digests, read back from the Server's own /log endpoint) and tries to recover
the clients' set elements by hashing candidate values and comparing.

Against the "plain" protocol of Question A.3 this succeeds, because:
  * the hash function is public and unkeyed, so the Server can compute it;
  * it is deterministic, so equal elements give equal digests;
  * the input domain (small integers, and a student number of known format)
    is tiny compared with the 2^256 output space.

Against the "hmac" improvement it fails, because the Server does not hold the
MAC key and therefore cannot compute the digest of any candidate at all.

Run with:   python3 psi/attack_bruteforce.py --session run1
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request

from common import digest_plain

DEFAULT_SERVER = "http://127.0.0.1:8214"


def fetch_log(server: str) -> list[dict]:
    with urllib.request.urlopen(f"{server}/log", timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))["messages"]


def harvest_digests(log: list[dict], session: str) -> dict[str, list[str]]:
    """Everything the Server holds for one session: client_id -> digests."""
    harvested: dict[str, list[str]] = {}
    for msg in log:
        if msg["session"] == session and msg["message"] == "BLINDED_SET":
            harvested[msg["peer"]] = msg["payload"]["digests"]
    return harvested


def brute_force(targets: set[str], candidates) -> tuple[dict[str, int], int]:
    """Hash each candidate and look for its digest among the targets."""
    recovered: dict[str, int] = {}
    tried = 0
    for candidate in candidates:
        tried += 1
        d = digest_plain(candidate)
        if d in targets:
            recovered[d] = candidate
            if len(recovered) == len(targets):
                break
    return recovered, tried


def main() -> None:
    parser = argparse.ArgumentParser(description="A.5 brute-force attack by the Server")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--session", default="run1")
    parser.add_argument("--small-range", type=int, default=10_000,
                        help="exhaustive search space for small integers")
    parser.add_argument("--id-hint", type=int, default=None,
                        help="a student-number prefix the Server is assumed to "
                             "know, e.g. 2407 for 2407xxxxx")
    parser.add_argument("--id-width", type=int, default=5,
                        help="number of unknown digits after the prefix")
    args = parser.parse_args()

    log = fetch_log(args.server)
    harvested = harvest_digests(log, args.session)
    if not harvested:
        raise SystemExit(f"no BLINDED_SET messages logged for session {args.session!r}")

    print("=" * 74)
    print(f"A.5  SERVER-SIDE BRUTE-FORCE ATTACK ON SESSION {args.session!r}")
    print("=" * 74)
    for client, digests in sorted(harvested.items()):
        print(f"  Server holds {len(digests)} digests from {client}")

    mode = next(m["payload"].get("mode") for m in log
                if m["session"] == args.session and m["message"] == "BLINDED_SET")
    print(f"  Blinding mode used by the clients: {mode}")
    print()

    if mode == "hmac":
        print("  The digests are HMAC-SHA256 under a key agreed between the two")
        print("  clients by Diffie-Hellman. The Server relayed the public values")
        print("  g^a and g^b but cannot compute g^ab, so it has no key.")
        print("  => the Server cannot compute the digest of ANY candidate value.")
        print("  => 0 of the elements can be recovered by hashing candidates.")
        print()
        print("  RESULT: attack fails.")
        return

    all_targets = {d for digests in harvested.values() for d in digests}

    # ---- Phase 1: exhaustive search over small integers --------------------
    print(f"  Phase 1: hash every integer in [0, {args.small_range}) and compare.")
    t0 = time.perf_counter()
    recovered, tried = brute_force(all_targets, range(args.small_range))
    t1 = time.perf_counter()
    rate = tried / max(t1 - t0, 1e-9)
    print(f"           {tried:,} candidates hashed in {t1 - t0:.2f}s "
          f"({rate:,.0f} hashes/second, single-threaded Python)")
    print()

    for client, digests in sorted(harvested.items()):
        found = {d: recovered[d] for d in digests if d in recovered}
        unknown = [d for d in digests if d not in recovered]
        print(f"  {client}: recovered {len(found)}/{len(digests)} elements")
        for d, value in sorted(found.items(), key=lambda kv: kv[1]):
            print(f"      {d[:24]}...  ->  {value}")
        for d in unknown:
            print(f"      {d[:24]}...  ->  NOT FOUND in this range")
    print()

    # ---- Phase 2: targeted search for the student number -------------------
    remaining = sorted(all_targets - set(recovered))
    if remaining:
        print(f"  Phase 2: {len(remaining)} digest(s) survived phase 1. These are")
        print("           consistent with a 9-digit student number. A student")
        print("           number is NOT secret and has a known format, so the")
        print("           Server can search that domain too.")
        if args.id_hint is not None:
            lo = args.id_hint * (10 ** args.id_width)
            hi = lo + (10 ** args.id_width)
            print(f"           Searching {lo:,}..{hi - 1:,} "
                  f"({10 ** args.id_width:,} candidates).")
            t0 = time.perf_counter()
            more, tried2 = brute_force(set(remaining), range(lo, hi))
            t1 = time.perf_counter()
            print(f"           {tried2:,} candidates hashed in {t1 - t0:.2f}s")
            for d, value in more.items():
                print(f"      {d[:24]}...  ->  {value}   <-- STUDENT NUMBER RECOVERED")
            recovered.update(more)
            remaining = sorted(all_targets - set(recovered))
        full_space = 10 ** 9
        print(f"           Even with no hint at all, the whole 9-digit space is")
        print(f"           {full_space:,} candidates: about "
              f"{full_space / rate / 3600:.1f} hours in this unoptimised Python,")
        print("           and seconds on a GPU. The domain, not the hash, is the")
        print("           weakness.")
    print()
    print(f"  RESULT: {len(recovered)}/{len(all_targets)} distinct digests inverted.")
    if remaining:
        print(f"          {len(remaining)} digest(s) still unknown "
              f"(outside the ranges searched here).")


if __name__ == "__main__":
    main()
