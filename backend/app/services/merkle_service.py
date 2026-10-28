"""Deterministic Merkle commitments with explicit domain separation.

Leaves encode evidence UUIDs as their 16 canonical UUID bytes and SHA-256
fingerprints as 32 raw bytes. The leaf preimage is 0x00 || id || fingerprint.
Internal nodes are 0x01 || left || right. Odd levels duplicate the last node.
The empty tree is SHA-256(0x02).
"""
import hashlib
import uuid
from dataclasses import dataclass

EMPTY_ROOT = hashlib.sha256(b"\x02").hexdigest()


def leaf_hash(evidence_id: str, sha256_hex: str) -> bytes:
    try:
        identifier = uuid.UUID(evidence_id).bytes
        digest = bytes.fromhex(sha256_hex)
    except (ValueError, TypeError) as exc:
        raise ValueError("evidence_id must be a UUID and sha256_hex must be hexadecimal") from exc
    if len(digest) != 32:
        raise ValueError("SHA-256 fingerprint must contain exactly 32 bytes")
    return hashlib.sha256(b"\x00" + identifier + digest).digest()


def parent_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle children must each be 32 bytes")
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[tuple[str, str]]) -> str:
    if not leaves:
        return EMPTY_ROOT
    level = [leaf_hash(evidence_id, digest) for evidence_id, digest in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [parent_hash(level[index], level[index + 1]) for index in range(0, len(level), 2)]
    return level[0].hex()


@dataclass(frozen=True)
class ProofNode:
    sibling_hash: str
    sibling_side: str  # left or right, relative to the current node


def inclusion_proof(leaves: list[tuple[str, str]], evidence_id: str) -> list[ProofNode]:
    if not leaves:
        raise ValueError("Cannot create a proof for the empty tree")
    index_matches = [i for i, (identifier, _) in enumerate(leaves) if identifier == evidence_id]
    if not index_matches:
        raise ValueError("Evidence is not in this Merkle tree")
    index = index_matches[0]
    level = [leaf_hash(identifier, digest) for identifier, digest in leaves]
    proof: list[ProofNode] = []
    while len(level) > 1:
        original_len = len(level)
        if original_len % 2:
            level.append(level[-1])
        sibling_index = index - 1 if index % 2 else index + 1
        proof.append(ProofNode(level[sibling_index].hex(), "left" if index % 2 else "right"))
        level = [parent_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        index //= 2
    return proof


def inclusion_proofs(leaves: list[tuple[str, str]]) -> dict[str, list[ProofNode]]:
    """Build proofs for a whole manifest in O(n log n), sharing tree levels."""
    if not leaves:
        return {}
    level = [leaf_hash(identifier, digest) for identifier, digest in leaves]
    proofs = {identifier: [] for identifier, _ in leaves}
    indices = {identifier: index for index, (identifier, _) in enumerate(leaves)}
    while len(level) > 1:
        actual_len = len(level)
        if actual_len % 2:
            level.append(level[-1])
        for identifier, index in indices.items():
            sibling_index = index - 1 if index % 2 else index + 1
            proofs[identifier].append(ProofNode(level[sibling_index].hex(), "left" if index % 2 else "right"))
            indices[identifier] = index // 2
        level = [parent_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return proofs


def verify_inclusion(evidence_id: str, sha256_hex: str, proof: list[ProofNode | dict[str, str]], expected_root: str) -> bool:
    try:
        current = leaf_hash(evidence_id, sha256_hex)
        for item in proof:
            if isinstance(item, dict):
                sibling, side = item["sibling_hash"], item["sibling_side"]
            else:
                sibling, side = item.sibling_hash, item.sibling_side
            sibling_bytes = bytes.fromhex(sibling)
            if side == "left":
                current = parent_hash(sibling_bytes, current)
            elif side == "right":
                current = parent_hash(current, sibling_bytes)
            else:
                return False
        return current.hex() == expected_root.lower()
    except (ValueError, KeyError, TypeError):
        return False
