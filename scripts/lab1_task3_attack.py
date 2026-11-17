"""Question C.2: the dictionary attack from Lab 1, Task 3.

Task 3 replaces encryption with a bare hash, cipher = SHA256(plaintext), and
supplies a ciphertext X together with a list of candidate passwords. Because
the transformation is unkeyed, deterministic and the candidate list is tiny,
the plaintext is recovered by hashing each candidate and comparing.

    python3 scripts/lab1_task3_attack.py
"""

from __future__ import annotations

import hashlib

X = "872715f9eb56b72a64f8f19b6297d54931d26bbc4923ccdd4354059a61dae80b"
CANDIDATES = ["11211223", "Password", "1989-Newcastle", "02.10.1999"]


def sha256_hex(text: str) -> str:
    """The lab's own construction: SHA-256 over the UTF-8 bytes, as hex."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main() -> None:
    print(f"X = {X}\n")
    print(f"{'candidate':<16} {'SHA-256(candidate)':<64}")
    print("-" * 82)

    recovered, tried = None, 0
    for candidate in CANDIDATES:
        tried += 1
        digest = sha256_hex(candidate)
        marker = "  <== MATCH" if digest == X else ""
        print(f"{candidate:<16} {digest:<64}{marker}")
        if digest == X:
            recovered = candidate
            break

    print("-" * 82)
    if recovered is None:
        print("no candidate matched X")
    else:
        print(f"plaintext Y = {recovered!r}, found after {tried} of "
              f"{len(CANDIDATES)} hashes")


if __name__ == "__main__":
    main()
