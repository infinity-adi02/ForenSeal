import hashlib
import uuid

import pytest

from app.services.merkle_service import EMPTY_ROOT, inclusion_proof, inclusion_proofs, merkle_root, verify_inclusion


def records(count):
    return [(str(uuid.UUID(int=i + 1)), hashlib.sha256(f"record-{i}".encode()).hexdigest()) for i in range(count)]


def test_empty_tree_is_stable():
    assert merkle_root([]) == EMPTY_ROOT
    assert len(EMPTY_ROOT) == 64


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 8, 11])
def test_proofs_cover_odd_and_even_trees(count):
    items = records(count)
    root = merkle_root(items)
    for evidence_id, fingerprint in items:
        assert verify_inclusion(evidence_id, fingerprint, inclusion_proof(items, evidence_id), root)
    shared = inclusion_proofs(items)
    assert all(verify_inclusion(evidence_id, digest, shared[evidence_id], root) for evidence_id, digest in items)


def test_tampered_fingerprint_and_proof_are_rejected():
    items = records(3)
    root = merkle_root(items)
    evidence_id, fingerprint = items[0]
    proof = inclusion_proof(items, evidence_id)
    changed = ("0" if fingerprint[0] != "0" else "1") + fingerprint[1:]
    assert not verify_inclusion(evidence_id, changed, proof, root)
    forged = [{"sibling_hash": "00" * 32, "sibling_side": "right"}]
    assert not verify_inclusion(evidence_id, fingerprint, forged, root)


def test_invalid_leaf_encodings_are_rejected():
    with pytest.raises(ValueError):
        merkle_root([("bad-id", "00" * 32)])
    with pytest.raises(ValueError):
        merkle_root([(str(uuid.uuid4()), "1234")])
