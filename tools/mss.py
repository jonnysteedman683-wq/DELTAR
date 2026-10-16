"""Merkle signature scheme over Lamport one-time keys (SHA-256). Stdlib only.

Hash-based, so it is post-quantum. One root signs up to 2**height messages;
each leaf key must be used exactly once. Every one-time key is derived from a
32-byte seed, so the seed is the only secret to store.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

N = 256          # message digest bits
HASH = 32        # bytes per hash
LEAF, NODE = b"\x00", b"\x01"   # domain separation


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sk(seed: bytes, index: int, bit: int, j: int) -> bytes:
    return hmac.new(seed, f"{index}:{bit}:{j}".encode(), hashlib.sha256).digest()


def _leaf_from_pk(pairs) -> bytes:
    return _h(LEAF + b"".join(p0 + p1 for p0, p1 in pairs))


def _leaf(seed: bytes, index: int) -> bytes:
    return _leaf_from_pk((_h(_sk(seed, index, 0, j)), _h(_sk(seed, index, 1, j))) for j in range(N))


def _bits(msg: bytes) -> list[int]:
    d = _h(msg)
    return [(d[j // 8] >> (7 - j % 8)) & 1 for j in range(N)]


def _tree(seed: bytes, height: int) -> list[list[bytes]]:
    level = [_leaf(seed, i) for i in range(2 ** height)]
    levels = [level]
    while len(level) > 1:
        level = [_h(NODE + level[k] + level[k + 1]) for k in range(0, len(level), 2)]
        levels.append(level)
    return levels


def public_root(seed: bytes, height: int) -> str:
    return _tree(seed, height)[-1][0].hex()


def sign(seed: bytes, height: int, index: int, msg: bytes) -> tuple[dict, str]:
    """Sign msg with one-time key `index`. Returns (signature, root_hex)."""
    if not 0 <= index < 2 ** height:
        raise ValueError("signing key exhausted or index out of range")
    levels = _tree(seed, height)
    path, k = [], index
    for level in levels[:-1]:
        path.append(level[k ^ 1].hex())
        k //= 2
    parts = []
    for j, bit in enumerate(_bits(msg)):
        parts.append(_sk(seed, index, bit, j))             # reveal the secret for this bit
        parts.append(_h(_sk(seed, index, 1 - bit, j)))     # public half for the other bit
    sig = {"key_index": index, "lamport": base64.b64encode(b"".join(parts)).decode(), "auth_path": path}
    return sig, levels[-1][0].hex()


def verify(root_hex: str, height: int, msg: bytes, sig: dict) -> bool:
    try:
        index = sig["key_index"]
        if set(sig) != {"key_index", "lamport", "auth_path"}:
            return False
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 2 ** height:
            return False
        raw = base64.b64decode(sig["lamport"], validate=True)
        if len(raw) != 2 * N * HASH or len(sig["auth_path"]) != height:
            return False
        pairs = []
        for j, bit in enumerate(_bits(msg)):
            first = raw[2 * j * HASH:(2 * j + 1) * HASH]
            second = raw[(2 * j + 1) * HASH:(2 * j + 2) * HASH]
            revealed = _h(first)
            pairs.append((revealed, second) if bit == 0 else (second, revealed))
        node, k = _leaf_from_pk(pairs), index
        for sib_hex in sig["auth_path"]:
            sib = bytes.fromhex(sib_hex)
            if len(sib) != HASH:
                return False
            node = _h(NODE + node + sib) if k % 2 == 0 else _h(NODE + sib + node)
            k //= 2
        return hmac.compare_digest(node.hex(), root_hex)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
