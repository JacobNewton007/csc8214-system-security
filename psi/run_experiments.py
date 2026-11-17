"""Question A.4: runs the whole of Part A and writes the outputs to results/.

    RUN 1   the sets given in the question
    RUN 2   Client 2's set modified so the intersection changes
    RUN 3   the sets of Run 1 with the keyed blinding of A.5
    ATTACK  the Server brute-forcing the Run 1 and Run 3 digests

Starts the Server itself unless one is already listening.

    python3 psi/run_experiments.py --student-id 260452597
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
from typing import Any

from client import Element, run_client

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"
DEFAULT_PORT = 8214
STARTUP_ATTEMPTS = 50
STARTUP_DELAY_SECONDS = 0.1


class Tee:
    """Mirror stdout into a transcript file."""

    def __init__(self, stream: Any, path: Path) -> None:
        self.stream = stream
        self.file = path.open("w", encoding="utf-8")

    def write(self, data: str) -> int:
        self.stream.write(data)
        self.file.write(data)
        return len(data)

    def flush(self) -> None:
        self.stream.flush()
        self.file.flush()

    def close(self) -> None:
        self.file.close()


def server_is_up(server: str) -> bool:
    try:
        with urllib.request.urlopen(f"{server}/health", timeout=1) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def start_server(server: str, port: int) -> subprocess.Popen[str] | None:
    if server_is_up(server):
        print(f"[runner] a Server is already listening on {server}")
        return None
    print(f"[runner] starting the Server on port {port} ...")
    process = subprocess.Popen(
        [sys.executable, str(HERE / "server.py"), "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(STARTUP_ATTEMPTS):
        if server_is_up(server):
            print(f"[runner] Server is up on {server}")
            return process
        time.sleep(STARTUP_DELAY_SECONDS)
    process.terminate()
    raise SystemExit("the Server failed to start")


def post(server: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{server}{path}", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def get(server: str, path: str) -> dict[str, Any]:
    with urllib.request.urlopen(f"{server}{path}", timeout=10) as response:
        return json.loads(response.read())


def banner(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


def run_session(server: str, session: str, mode: str,
                set1: list[Element], set2: list[Element]) -> dict[str, Any]:
    """Run both clients concurrently, as two independent parties."""
    results: dict[str, Any] = {}
    errors: list[BaseException] = []

    def worker(client_id: str, elements: list[Element]) -> None:
        try:
            results[client_id] = run_client(client_id, elements, mode, session, server)
        except BaseException as exc:  # re-raised in the main thread below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=args)
               for args in (("client1", set1), ("client2", set2))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise errors[0]
    return results


def print_server_view(server: str, session: str) -> list[dict[str, Any]]:
    """Print exactly what the Server received and sent for one session."""
    log = [m for m in get(server, "/log")["messages"] if m["session"] == session]
    print(f"\n--- MESSAGES AT THE SERVER for session {session!r} "
          "(this is the Server's ENTIRE view) ---")
    for message in log:
        arrow = "<--" if message["direction"] == "received" else "-->"
        print(f"  [{message['seq']:>2}] {message['time']}  "
              f"Server {arrow} {message['peer']:<12} {message['message']}")
        payload = message["payload"]
        if message["message"] == "BLINDED_SET":
            print(f"        mode={payload['mode']}  count={payload['count']}")
        elif message["message"] == "INTERSECTION":
            print(f"        count={payload['count']}")
        else:
            print(f"        {payload}")
            continue
        for element_digest in payload["digests"]:
            print(f"          {element_digest}")
    print("  NOTE: no raw set element appears anywhere above.")
    return log


def parse_student_id(raw: str) -> Element:
    """Keep the ID numeric when it is, but tolerate a letter prefix."""
    value = raw.strip()
    return int(value) if value.lstrip("-").isdigit() else value


def main() -> None:
    parser = argparse.ArgumentParser(description="CSC8214 Part A experiment runner")
    parser.add_argument("--student-id",
                        default=os.environ.get("CSC8214_STUDENT_ID", "260452597"))
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--server", default=None)
    args = parser.parse_args()

    server = args.server or f"http://127.0.0.1:{args.port}"
    student_id = parse_student_id(args.student_id)

    RESULTS.mkdir(exist_ok=True)
    tee = Tee(sys.stdout, RESULTS / "transcript.txt")
    sys.stdout = tee

    process = None
    try:
        process = start_server(server, args.port)
        post(server, "/reset", {})

        set1: list[Element] = [1, 2, 5, 9, student_id]
        set2: list[Element] = [5, 8, 11, student_id]
        # A.4(ii): 5 removed and 2 added, so the intersection must change.
        set2_modified: list[Element] = [2, 8, 11, student_id]

        runs = [
            ("run1", "plain", set1, set2,
             "RUN 1 (A.4 i) - the sets given in the question, plain SHA-256",
             [f"  Client 1 set: {{1, 2, 5, 9, ID}}  with ID = {student_id}",
              f"  Client 2 set: {{5, 8, 11, ID}}    with ID = {student_id}",
              f"  Expected intersection: {{5, {student_id}}}"]),
            ("run2", "plain", set1, set2_modified,
             "RUN 2 (A.4 ii) - Client 2's set modified, plain SHA-256",
             ["  Client 1 set: {1, 2, 5, 9, ID}  (unchanged)",
              "  Client 2 set: {2, 8, 11, ID}    (5 removed, 2 added)",
              f"  Expected intersection: {{2, {student_id}}}"]),
            ("run3", "hmac", set1, set2,
             "RUN 3 (A.5 improvement) - same sets as Run 1, keyed HMAC-SHA256",
             ["  The two clients first agree a key by Diffie-Hellman, relayed by",
              "  the Server. The Server sees g^a and g^b but cannot derive g^ab."]),
        ]

        all_results: dict[str, Any] = {}
        for session, mode, first, second, title, preamble in runs:
            banner(title)
            print("\n".join(preamble))
            print()
            clients = run_session(server, session, mode, first, second)
            key = "run3_hmac" if session == "run3" else session
            all_results[key] = {"clients": clients,
                                "server_log": print_server_view(server, session)}

        # The Server is assumed to know all but the last five characters of a
        # student number, which is not a secret in the first place.
        id_prefix = str(student_id)[:-5]
        for session in ("run1", "run3"):
            print()
            attack = subprocess.run(
                [sys.executable, str(HERE / "attack_bruteforce.py"),
                 "--server", server, "--session", session,
                 "--id-prefix", id_prefix, "--id-width", "5"],
                capture_output=True, text=True, cwd=str(HERE), check=False)
            print(attack.stdout, end="")
            if attack.stderr:
                print(attack.stderr, end="", file=sys.stderr)

        banner("SUMMARY")
        for name, payload in all_results.items():
            first = payload["clients"]["client1"]["intersection"]
            second = payload["clients"]["client2"]["intersection"]
            print(f"  {name:<10} client1 output = {first}")
            print(f"  {'':<10} client2 output = {second}")
            print(f"  {'':<10} both clients agree: {first == second}")

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
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            print("[runner] Server stopped")


if __name__ == "__main__":
    main()
