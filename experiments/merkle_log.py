# experiments/merkle_log.py
"""
WARNING:
This is an experimental Merkle integrity layer.
It is not yet part of the core DNSProof trust guarantees.
Schema and algorithm may change.

Root publication currently depends on DNS integrity; future versions may sign the root itself using the active signing key.

Merkle Specification v1:
- Leaf hash = sha256("leaf:" + snapshot_hash)
- Hash function = SHA256 hex lowercase
- Parent hash = sha256("node:" + left_hex + right_hex)
- If odd number of nodes: duplicate last
- Order = (created_at ASC, id ASC)
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import hashlib
from sqlmodel import Session, select
from models.models import DNSChangeLog
from utils.db import engine
from typing import List, Tuple

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def leaf_hash(snapshot_hash: str) -> str:
    return sha256_hex("leaf:" + snapshot_hash)


def node_hash(left: str, right: str) -> str:
    return sha256_hex("node:" + left + right)

def get_ordered_snapshot_hashes(domain: str) -> List[Tuple[str, str]]:
    """
    Returns list of (log_id, snapshot_hash)
    Ordered deterministically.
    """
    with Session(engine) as session:
        logs = session.exec(
            select(DNSChangeLog)
            .where(DNSChangeLog.domain == domain)
            .order_by(DNSChangeLog.created_at.asc(), DNSChangeLog.id.asc())
        ).all()

        return [(log.id, log.snapshot_hash) for log in logs]


def build_merkle_tree(leaves: List[str]) -> List[List[str]]:
    """
    Returns full tree as list of levels.
    Level 0 = leaves
    Last level = root
    """
    if not leaves:
        return []

    current = [leaf_hash(leaf) for leaf in leaves]
    tree = [current]

    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])  # duplicate last

        next_level = []

        for i in range(0, len(current), 2):
            next_level.append(node_hash(current[i], current[i+1]))

        tree.append(next_level)
        current = next_level

    return tree


def get_merkle_root(tree: List[List[str]]) -> str:
    if not tree:
        return None
    return tree[-1][0]


def get_inclusion_proof(tree: List[List[str]], index: int) -> List[str]:
    """
    Returns list of sibling hashes needed to verify leaf.
    """
    proof = []
    for level in tree[:-1]:
        if index % 2 == 0:
            sibling_index = index + 1
        else:
            sibling_index = index - 1

        if sibling_index < len(level):
            proof.append(level[sibling_index])
        else:
            proof.append(level[index])  # duplicated leaf case

        index = index // 2

    return proof


def verify_proof(leaf: str, proof: List[str], root: str, index: int) -> bool:
    current = leaf_hash(leaf)

    for sibling in proof:
        if index % 2 == 0:
            current = node_hash(current, sibling)
        else:
            current = node_hash(sibling, current)
        index = index // 2

    return current == root


if __name__ == "__main__":
    domain = input("Domain: ").strip()

    entries = get_ordered_snapshot_hashes(domain)

    if not entries:
        print("No log entries found.")
        exit()

    ids = [e[0] for e in entries]
    leaves = [e[1] for e in entries]

    tree = build_merkle_tree(leaves)
    root = get_merkle_root(tree)

    print("\nMerkle Root:")
    print(root)

    # Pick one entry for proof demo
    target_id = ids[0]
    index = 0

    proof = get_inclusion_proof(tree, index)

    print(f"\nProof for log_id: {target_id}")
    print(proof)

    is_valid = verify_proof(leaves[index], proof, root, index)

    print("\nVerification result:", is_valid)