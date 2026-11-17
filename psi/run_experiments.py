"""
CSC8214 System Security - Assignment Question A.4 (implementation and testing).

Orchestrates the whole of Part A:

  RUN 1  the sets given in the question:  C1 = {1,2,5,9,ID}   C2 = {5,8,11,ID}
  RUN 2  Client 2's set modified so the intersection changes (A.4 ii)
  RUN 3  the same sets as Run 1 but with the A.5 privacy improvement (HMAC)
  ATTACK the Server brute-forces the Run 1 digests, then the Run 3 digests

It starts the Server automatically if one is not already listening, runs the
two clients concurrently in threads, prints everything each party sees, and
writes machine-readable copies into results/.

Run with:   python3 psi/run_experiments.py --student-id 240123456
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from client import run_client

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = ROOT / "results"
DEFAULT_SERVER = "http://127.0.0.1:8214"


class Tee:
    """Write everything printed to both the terminal and a transcript file."""

    def __init__(self, stream, path: Path):
        self.stream = stream
        self.file = path.open("w", encoding="utf-8")

    def write(self, data):
        self.stream.write(data)
        self.file.write(data)
        return len(data)

    def flush(self):
        self.stream.flush()
        self.file.flush()

    def close(self):
        self.file.close()


def server_is_up(server: str) -> bool:
    try:
        with urllib.request.urlopen(f"{server}/health", timeout=1) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def start_server(server: str, port: int) -> subprocess.Popen | None:
    """Start the Server unless one is already listening."""
    if server_is_up(server):
        print(f"[runner] a Server is already listening on {server}")
        return None
    print(f"[runner] starting the Server on port {port} ...")
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "server.py"), "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    for _ in range(50):
        if server_is_up(server):
            print(f"[runner] Server is up on {server}")
            return proc
        time.sleep(0.1)
    proc.terminate()
    raise SystemExit("the Server failed to start")


def post(server: str, path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"{server}{path}", data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get(server: str, path: str) -> dict:
    with urllib.request.urlopen(f"{server}{path}", timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def banner(title: str) -> None:
    print()
    print("=" * 74)
    print(title)
    print("=" * 74)


def run_session(server: str, session: str, mode: str, set1: list, set2: list) -> dict:
    """Run both clients concurrently against the Server."""
    results: dict[str, dict] = {}
    errors: list[BaseException] = []

    def worker(client_id: str, elements: list) -> None:
        try:
            results[client_id] = run_client(client_id, elements, mode, session, server)
        except BaseException as exc:  # noqa: BLE001 - surface it in the main thread
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=("client1", set1)),
        threading.Thread(target=worker, args=("client2", set2)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise errors[0]
    return results


def print_server_view(server: str, session: str) -> list[dict]:
    """Print exactly what the Server received and sent for one session."""
    log = [m for m in get(server, "/log")["messages"] if m["session"] == session]
    print()
    print(f"--- MESSAGES AT THE SERVER for session {session!r} "
          f"(this is the Server's ENTIRE view) ---")
    for msg in log:
        arrow = "<--" if msg["direction"] == "received" else "-->"
        print(f"  [{msg['seq']:>2}] {msg['time']}  Server {arrow} {msg['peer']:<12} "
              f"{msg['message']}")
        payload = msg["payload"]
        if msg["message"] == "BLINDED_SET":
            print(f"        mode={payload['mode']}  count={payload['count']}")
            for d in payload["digests"]:
                print(f"          {d}")
        elif msg["message"] == "INTERSECTION":
            print(f"        count={payload['count']}")
            for d in payload["digests"]:
                print(f"          {d}")
        else:
            print(f"        {payload}")
    print("  NOTE: no raw set element appears anywhere above.")
    return log


def main() -> None:
    parser = argparse.ArgumentParser(description="CSC8214 Part A experiment runner")
    parser.add_argument("--student-id", default=os.environ.get("CSC8214_STUDENT_ID", "240000000"),
                        help="your student number (the element called ID in the question)")
    parser.add_argument("--port", type=int, default=8214)
    parser.add_argument("--server", default=None)
    args = parser.parse_args()

    server = args.server or f"http://127.0.0.1:{args.port}"
    student_id = int(args.student_id)

    RESULTS.mkdir(exist_ok=True)
    tee = Tee(sys.stdout, RESULTS / "transcript.txt")
    sys.stdout = tee

    proc = None
    try:
        proc = start_server(server, args.port)
        post(server, "/reset", {})

        set1 = [1, 2, 5, 9, student_id]
        set2 = [5, 8, 11, student_id]
        # A.4(ii): Client 2 drops 5 and adds 2, so the intersection must change
        # from {5, ID} to {2, ID}.
        set2_modified = [2, 8, 11, student_id]

        all_results: dict[str, dict] = {}

        # ---------------- RUN 1 ---------------------------------------------
        banner("RUN 1 (A.4 i) - the sets given in the question, plain SHA-256")
        print(f"  Client 1 set: {{1, 2, 5, 9, ID}}  with ID = {student_id}")
        print(f"  Client 2 set: {{5, 8, 11, ID}}    with ID = {student_id}")
        print(f"  Expected intersection: {{5, {student_id}}}")
        print()
        r1 = run_session(server, "run1", "plain", set1, set2)
        log1 = print_server_view(server, "run1")
        all_results["run1"] = {"clients": r1, "server_log": log1}

        # ---------------- RUN 2 ---------------------------------------------
        banner("RUN 2 (A.4 ii) - Client 2's set modified, plain SHA-256")
        print(f"  Client 1 set: {{1, 2, 5, 9, ID}}  (unchanged)")
        print(f"  Client 2 set: {{2, 8, 11, ID}}    (5 removed, 2 added)")
        print(f"  Expected intersection: {{2, {student_id}}}")
        print()
        r2 = run_session(server, "run2", "plain", set1, set2_modified)
        log2 = print_server_view(server, "run2")
        all_results["run2"] = {"clients": r2, "server_log": log2}

        # ---------------- RUN 3 ---------------------------------------------
        banner("RUN 3 (A.5 improvement) - same sets as Run 1, keyed HMAC-SHA256")
        print("  The two clients first agree a key by Diffie-Hellman, relayed by")
        print("  the Server. The Server sees g^a and g^b but cannot derive g^ab.")
        print()
        r3 = run_session(server, "run3", "hmac", set1, set2)
        log3 = print_server_view(server, "run3")
        all_results["run3_hmac"] = {"clients": r3, "server_log": log3}

        # ---------------- ATTACKS -------------------------------------------
        id_hint = student_id // 100_000  # the Server is assumed to know the prefix
        for session in ("run1", "run3"):
            print()
            attack = subprocess.run(
                [sys.executable, str(HERE / "attack_bruteforce.py"),
                 "--server", server, "--session", session,
                 "--id-hint", str(id_hint), "--id-width", "5"],
                capture_output=True, text=True, cwd=str(HERE),
            )
            print(attack.stdout, end="")
            if attack.stderr:
                print(attack.stderr, end="", file=sys.stderr)

        # ---------------- SUMMARY -------------------------------------------
        banner("SUMMARY")
        for name, payload in all_results.items():
            c1 = payload["clients"]["client1"]["intersection"]
            c2 = payload["clients"]["client2"]["intersection"]
            print(f"  {name:<10} client1 output = {c1}")
            print(f"  {'':<10} client2 output = {c2}")
            print(f"  {'':<10} both clients agree: {c1 == c2}")

        (RESULTS / "results.json").write_text(
            json.dumps(all_results, indent=2, default=str), encoding="utf-8")
        (RESULTS / "server_log_full.json").write_text(
            json.dumps(get(server, "/log"), indent=2), encoding="utf-8")
        print()
        for name in ("results.json", "server_log_full.json", "transcript.txt"):
            print(f"  Written: results/{name}")
    finally:
        sys.stdout = tee.stream
        tee.close()
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            print("[runner] Server stopped")


if __name__ == "__main__":
    main()
