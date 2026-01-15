import dns.message
import dns.query
import dns.rdatatype
import random
from config import NS1

ROOT_SERVERS = [
    "198.41.0.4",     # a.root-servers.net
    "199.9.14.201",   # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
    "199.7.91.13",    # d.root-servers.net
    "192.203.230.10", # e.root-servers.net
    "192.5.5.241",     # f
    "192.112.36.4",    # g
    "198.97.190.53",   # h
    "192.36.148.17",   # i
    "192.58.128.30",   # j
    "193.0.14.129",    # k
    "199.7.83.42",     # l
    "202.12.27.33",    # m
]

EXPECTED_NS = {NS1}

def query_ns_direct(ip: str, domain: str, timeout: int = 3):
    """
    Sends a direct NS query to a specific nameserver IP.
    Equivalent to: dig @$IP <domain> NS +short
    """
    try:
        query = dns.message.make_query(domain, dns.rdatatype.NS)
        response = dns.query.udp(query, ip, timeout=timeout)
        ns_records = []

        for answer in response.answer:
            if answer.rdtype == dns.rdatatype.NS:
                ns_records.extend([r.to_text() for r in answer])

        return ns_records
    except Exception as e:
        return {"error": str(e)}

def trace_ns(domain):
    qname = dns.name.from_text(domain)
    current_servers = random.sample(ROOT_SERVERS, len(ROOT_SERVERS))
    depth = 0

    while True:
        depth += 1
        query = dns.message.make_query(qname, dns.rdatatype.NS)

        for server in current_servers:
            try:
                print(f"[Step {depth}] Querying {server} for NS of {qname}")
                response = dns.query.udp(query, server, timeout=3)

                # If we get an answer, we've reached the authoritative zone
                all_targets = set()
                if response.answer:
                    print("✅ Final NS answer:")
                    for rrset in response.answer:
                        print(rrset)
                        if rrset.rdtype == dns.rdatatype.NS:
                            for rdata in rrset:
                                target = str(rdata.target).lower().rstrip('.') + '.'
                                all_targets.add(target)

                    print(f"Returned NS: {all_targets}")
                    all_targets = {str(rdata.target).strip('.').lower() for rdata in rrset}
                    expected = {ns.strip('.').lower() for ns in EXPECTED_NS}
                    if expected.issubset(all_targets):
                        return {
                            "status": True,
                            "resolved_ns": sorted(all_targets),
                            "depth": depth,
                            "trace_success": True
                        }
                    else:
                        return {
                            "status": False,
                            "resolved_ns": sorted(all_targets),
                            "depth": depth,
                            "trace_success": True
                        }
                    '''
                    if all(ns in all_targets for ns in EXPECTED_NS):
                        return True
                    else:
                        return False
                    '''

                # Otherwise, follow delegation from authority section
                authority_rrset = next((rr for rr in response.authority if rr.rdtype == dns.rdatatype.NS), None)
                if not authority_rrset:
                    raise Exception("No NS delegation found")

                next_ns_names = [str(rr.target) for rr in authority_rrset]
                current_servers = []

                # Resolve the IPs of the next NS servers using system resolver
                for ns in next_ns_names:
                    try:
                        ip = dns.resolver.resolve(ns, 'A')[0].to_text()
                        current_servers.append(ip)
                    except Exception as e:
                        print(f"❌ Failed to resolve {ns}: {e}")
                break  # go to next depth level

            except Exception as e:
                print(f"❌ Query to {server} failed: {e}")
                continue

        if not current_servers:
            raise Exception("No working NS servers found for next step.")
