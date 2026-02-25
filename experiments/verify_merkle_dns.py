"""
WARNING:
This is an experimental Merkle integrity layer.
It is not yet part of the core DNSProof trust guarantees.
Schema and algorithm may change.

Root publication currently depends on DNS integrity; future versions may sign the root itself using the active signing key.

Merkle Specification v1:
- Leaves = sha256(snapshot_hash)
- Hash function = SHA256 hex lowercase
- Parent hash = sha256(left_hex + right_hex)
- If odd number of nodes: duplicate last
- Order = (created_at ASC, id ASC)
"""
import hashlib
from typing import List, Tuple, Optional

import dns.resolver

# --- Your project imports (works with your sys.path hack style) ---
import sys
from pathlib import Path

# Add project root so we can import app modules when running directly
sys.path.append(str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select, and_, not_
from models.models import DNSChangeLog
from utils.db import engine
import dns.message
import dns.query
import dns.rdatatype

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def leaf_hash(snapshot_hash: str) -> str:
    return sha256_hex("leaf:" + snapshot_hash)


def node_hash(left: str, right: str) -> str:
    return sha256_hex("node:" + left + right)

def get_ordered_snapshot_hashes(domain: str) -> List[Tuple[str, str]]:
    """
    Returns list of (log_id, snapshot_hash), deterministically ordered.
    """
    with Session(engine) as session:
        logs = session.exec(
            select(DNSChangeLog)
            .where(
                and_(
                    DNSChangeLog.domain == domain,
                    not_(
                        and_(
                            DNSChangeLog.record_type == "TXT",
                            DNSChangeLog.record_name == "_merkle"
                        )
                    )
                )
            )
            .order_by(DNSChangeLog.created_at.asc(), DNSChangeLog.id.asc())
        ).all()

    return [(log.id, log.snapshot_hash) for log in logs]


def build_merkle_tree_from_snapshot_hashes(snapshot_hashes: List[str]) -> List[List[str]]:
    """
    Level 0 = leaf hashes (sha256(snapshot_hash))
    Each parent = sha256(left + right)
    """
    if not snapshot_hashes:
        return []

    level = [leaf_hash(h) for h in snapshot_hashes]
    tree = [level]

    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]  # duplicate last

        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(node_hash(level[i], level[i + 1]))

        tree.append(next_level)
        level = next_level

    return tree


def merkle_root(snapshot_hashes: List[str]) -> Optional[str]:
    tree = build_merkle_tree_from_snapshot_hashes(snapshot_hashes)
    if not tree:
        return None
    return tree[-1][0]


def normalize_root(s: str) -> str:
    """
    Strip quotes/spaces, lowercase, and validate looks like hex.
    """
    s = s.strip().strip('"').strip("'").lower()
    return s


def fetch_txt_root(domain: str, txt_name: str = "_merkle", resolver_ip: Optional[str] = "1.1.1.1") -> Optional[str]:
    """
    Queries TXT record at <txt_name>.<domain>.
    Returns first TXT value (joined if split into multiple strings).
    """
    fqdn = f"{txt_name}.{domain}".strip(".")
    r = dns.resolver.Resolver()
    if resolver_ip:
        r.nameservers = [resolver_ip]
    r.timeout = 2.0
    r.lifetime = 3.5

    try:
        answers = r.resolve(fqdn, "TXT")
    except Exception as e:
        print(f"[DNS] TXT lookup failed for {fqdn}: {e}")
        return None

    # dnspython may return TXT as multiple strings; join them.
    for rr in answers:
        chunks = []
        for b in rr.strings:
            chunks.append(b.decode("utf-8", errors="replace"))
        txt_value = "".join(chunks)
        return normalize_root(txt_value)

    return None

def fetch_txt_root_direct(domain: str, ns_ip: str, txt_name: str = "_merkle", timeout: float = 2.0) -> Optional[str]:
    """
    Directly query a specific nameserver IP for TXT at <txt_name>.<domain>.
    Equivalent to: dig @<ns_ip> TXT _merkle.<domain>
    """
    fqdn = f"{txt_name}.{domain}".strip(".") + "."

    q = dns.message.make_query(fqdn, dns.rdatatype.TXT)
    try:
        resp = dns.query.udp(q, ns_ip, timeout=timeout)
    except Exception as e:
        print(f"[DNS] UDP query failed to {ns_ip}: {e}")
        return None

    # If TC bit set, retry over TCP
    if resp.flags & dns.flags.TC:
        try:
            resp = dns.query.tcp(q, ns_ip, timeout=timeout)
        except Exception as e:
            print(f"[DNS] TCP retry failed to {ns_ip}: {e}")
            return None

    # Parse answers
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.TXT:
            for rdata in rrset:
                # dnspython TXT can be multiple strings; join
                chunks = [b.decode("utf-8", errors="replace") for b in rdata.strings]
                return normalize_root("".join(chunks))

    print(f"[DNS] No TXT answer found for {fqdn} from {ns_ip}")
    return None

def main():
    domain = input("Domain: ").strip().lower()
    if not domain:
        print("Missing domain.")
        return

    entries = get_ordered_snapshot_hashes(domain)
    if not entries:
        print("[LOCAL] No DNSChangeLog entries found for this domain.")
        return

    snapshot_hashes = [h for (_id, h) in entries]
    local_root = merkle_root(snapshot_hashes)
    if not local_root:
        print("[LOCAL] Could not compute local root.")
        return

    # resolver version
    #dns_root = fetch_txt_root(domain, txt_name="_merkle", resolver_ip="1.1.1.1")
    # direct fetch version
    ns_ip = input("Nameserver IP (e.g. 34.66.203.123): ").strip()
    dns_root = fetch_txt_root_direct(domain, ns_ip=ns_ip, txt_name="_merkle")

    print("\nLocal Merkle Root:")
    print(local_root)

    print("\nDNS TXT Root (_merkle.<domain>):")
    print(dns_root if dns_root else "(missing)")

    if dns_root and normalize_root(local_root) == normalize_root(dns_root):
        print("\n✅ Match: DNS TXT root equals local Merkle root")
    else:
        print("\n❌ Mismatch (or missing TXT): roots differ")


if __name__ == "__main__":
    main()