"""
CSC8214 System Security - Assignment Part A (Private Set Intersection)

Shared helpers used by the Server and by both Clients.

The protocol has two modes, both of which are discussed in the report:

  mode = "plain"  -> digest = SHA-256(TAG || element)
                     This is the protocol specified in Question A.3: a plain
                     cryptographic hash function is used as the "blinding"
                     step. It hides the elements from a passive observer but,
                     as Question A.5 shows, NOT from a Server that is willing
                     to hash candidate values (the input domain is tiny).

  mode = "hmac"   -> digest = HMAC-SHA256(k, TAG || element)
                     This is the privacy improvement discussed in A.5. The key
                     k is derived by a Diffie-Hellman exchange between Client 1
                     and Client 2 only. The Server relays the two public keys
                     but, without the discrete log, cannot derive k, so it can
                     no longer brute-force candidate values.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

# Domain-separation tag. Both clients must use exactly the same tag, otherwise
# equal elements would produce different digests and the intersection would be
# empty. It also stops digests from this protocol being replayed into another
# protocol that hashes the same values.
TAG = b"CSC8214-PSI-v1|"

# ---------------------------------------------------------------------------
# Canonical encoding
# ---------------------------------------------------------------------------
# PSI over hashes only works if both clients encode an element to the exact same
# byte string. "5", 5 and " 5" must not produce three different digests, so a
# single canonical encoding is fixed here and used by both clients.


def encode_element(element) -> bytes:
    """Canonical byte encoding of a set element (integers and strings)."""
    if isinstance(element, bool):  # bool is a subclass of int - reject it
        raise TypeError("boolean set elements are not supported")
    if isinstance(element, int):
        return str(element).encode("utf-8")
    if isinstance(element, str):
        return element.strip().encode("utf-8")
    raise TypeError(f"unsupported element type: {type(element).__name__}")


# ---------------------------------------------------------------------------
# PROTOCOL STEP 2 (blinding): element -> digest
# ---------------------------------------------------------------------------


def digest_plain(element) -> str:
    """SHA-256 digest of a single element (unkeyed - the A.3 protocol)."""
    return hashlib.sha256(TAG + encode_element(element)).hexdigest()


def digest_keyed(element, key: bytes) -> str:
    """HMAC-SHA256 digest of a single element (keyed - the A.5 improvement)."""
    return hmac.new(key, TAG + encode_element(element), hashlib.sha256).hexdigest()


def digest(element, key: bytes | None = None) -> str:
    """Dispatch to the keyed or unkeyed digest depending on whether a key is set."""
    return digest_plain(element) if key is None else digest_keyed(element, key)


def blind_set(elements, key: bytes | None = None) -> dict[str, object]:
    """
    Blind a whole set.

    Returns a *local lookup table* {digest: element}. The table never leaves the
    client; only its keys (the digests) are sent to the Server. The table is what
    lets the client invert the Server's answer in PROTOCOL STEP 5.
    """
    table: dict[str, object] = {}
    for element in elements:
        table[digest(element, key)] = element
    return table


# ---------------------------------------------------------------------------
# PROTOCOL STEP 1 (optional, "hmac" mode only): client-to-client key agreement
# ---------------------------------------------------------------------------
# A 2048-bit MODP group from RFC 3526. Diffie-Hellman is run *between the two
# clients*; the Server only forwards the public values g^a and g^b. Deriving the
# shared secret g^ab from those two public values is the Diffie-Hellman problem,
# which the Server cannot solve, so the Server never learns the MAC key.

DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
    "FFFFFFFF",
    16,
)
DH_GENERATOR = 2


def dh_keypair() -> tuple[int, int]:
    """Generate a Diffie-Hellman keypair (private, public)."""
    private = secrets.randbits(256)
    public = pow(DH_GENERATOR, private, DH_PRIME)
    return private, public


def dh_shared_key(private: int, peer_public: int) -> bytes:
    """Derive a 256-bit MAC key from the DH shared secret."""
    if not 1 < peer_public < DH_PRIME - 1:
        raise ValueError("invalid peer public key")
    shared = pow(peer_public, private, DH_PRIME)
    raw = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
    # Hash the raw group element into a uniform 32-byte key (a simple KDF).
    return hashlib.sha256(b"CSC8214-PSI-KDF|" + raw).digest()
