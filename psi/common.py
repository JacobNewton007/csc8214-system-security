"""Shared primitives for the CSC8214 private set intersection protocol.

Two blinding modes are supported:

    plain  digest = SHA-256(TAG || element)           the protocol of A.3
    hmac   digest = HMAC-SHA256(k, TAG || element)    the improvement of A.5

In hmac mode the key is agreed between the two clients by Diffie-Hellman, so
the Server cannot compute the digest of a candidate value.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

Element = int | str

# Domain separation. Both clients must use the same tag or no digests match.
TAG = b"CSC8214-PSI-v1|"

# RFC 3526 2048-bit MODP group.
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
DH_PRIVATE_BITS = 256


def encode_element(element: Element) -> bytes:
    """Canonical encoding, so that both clients hash an element identically."""
    if isinstance(element, bool):
        raise TypeError("boolean set elements are not supported")
    if isinstance(element, int):
        return str(element).encode()
    if isinstance(element, str):
        return element.strip().encode()
    raise TypeError(f"unsupported element type: {type(element).__name__}")


def digest(element: Element, key: bytes | None = None) -> str:
    """PROTOCOL STEP 1 - blind one element, keyed if a key is supplied."""
    message = TAG + encode_element(element)
    if key is None:
        return hashlib.sha256(message).hexdigest()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def blind_set(elements: list[Element], key: bytes | None = None) -> dict[str, Element]:
    """Blind a set, returning the client-private table {digest: element}."""
    return {digest(element, key): element for element in elements}


def dh_keypair() -> tuple[int, int]:
    """Return a Diffie-Hellman (private, public) pair."""
    private = secrets.randbits(DH_PRIVATE_BITS)
    return private, pow(DH_GENERATOR, private, DH_PRIME)


def dh_shared_key(private: int, peer_public: int) -> bytes:
    """Derive the 256-bit MAC key from a peer's public value."""
    if not 1 < peer_public < DH_PRIME - 1:
        raise ValueError("invalid peer public key")
    shared = pow(peer_public, private, DH_PRIME)
    raw = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
    return hashlib.sha256(b"CSC8214-PSI-KDF|" + raw).digest()
