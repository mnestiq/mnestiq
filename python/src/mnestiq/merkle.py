"""Merkle tree hashing per RFC 9162 (Certificate Transparency v2), section 2.1.

Leaves are the raw 32-byte record hashes. Domain separation (0x00 for leaves,
0x01 for interior nodes) prevents second-preimage attacks.
"""

from __future__ import annotations

import hashlib


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = [_leaf(x) for x in leaves]
    return _root(level)


def _root(nodes: list[bytes]) -> bytes:
    if len(nodes) == 1:
        return nodes[0]
    k = 1
    while k * 2 < len(nodes):
        k *= 2  # largest power of two strictly less than len(nodes)
    return _node(_root(nodes[:k]), _root(nodes[k:]))
