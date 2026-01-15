import dns.message
import dns.query
import dns.rdatatype
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
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

                # Otherwise, follow delegation from authority section
                authority_rrset = next((rr for rr in response.authority if rr.rdtype == dns.rdatatype.NS), None)
                if not authority_rrset:
                    raise Exception("No NS delegation found")

                next_ns_names = [str(rr.target) for rr in authority_rrset]
                current_servers = []

                # Resolve the IPs of the next NS servers using system resolver
                for ns in next_ns_names:
                    try:
                        # First try system resolver (common case)
                        ip = dns.resolver.resolve(ns, 'A')[0].to_text()
                        current_servers.append(ip)
                    except Exception as e1:
                        try:
                            ip = dns.resolver.resolve(ns, 'AAAA')[0].to_text()
                            current_servers.append(ip)
                        except Exception as e2:
                            # Try to get glue record from additional section
                            glue_ip = None
                            for rr in response.additional:
                                rr_name = str(rr.name).rstrip('.').lower()
                                ns_clean = ns.rstrip('.').lower()
                                if rr.rdtype == dns.rdatatype.A and rr_name == ns_clean:
                                    glue_ip = rr[0].address
                                    break
                                if rr.rdtype == dns.rdatatype.AAAA and rr_name == ns_clean:
                                    glue_ip = rr[0].address
                                    break

                            if glue_ip:
                                current_servers.append(glue_ip)
                            else:
                                print(f"❌ Could not resolve {ns}: {e1} / {e2}")
                break  # go to next depth level
                
                
            except Exception as e:
                print(f"❌ Query to {server} failed: {e}")
                continue

        if not current_servers:
            raise Exception("No working NS servers found for next step.")

def check_ns_propagation_status(domain: str, expected_ns: set):
    """
    Checks whether expected nameservers have propagated by performing a trace
    from the root down to the domain.

    Returns a structured propagation status report.
    """
    try:
        trace_result = trace_ns(domain)
        resolved_ns = trace_result.get("resolved_ns", [])
        depth = trace_result.get("depth", None)
        trace_success = trace_result.get("trace_success", False)

        if not trace_success:
            return {
                "domain": domain,
                "resolved_ns": resolved_ns,
                "expected_ns": list(expected_ns),
                "match": False,
                "depth": depth,
                "status": "trace_failed",
                "explanation": "Could not complete DNS trace to domain"
            }

        normalized_resolved = {ns.strip('.').lower() for ns in resolved_ns}
        normalized_expected = {ns.strip('.').lower() for ns in expected_ns}

        if normalized_expected.issubset(normalized_resolved):
            status = "fully_propagated"
            explanation = "All expected nameservers found in final NS record"
            match = True
        elif normalized_resolved & normalized_expected:
            status = "partially_propagated"
            explanation = "Some expected nameservers found, still propagating"
            match = False
        else:
            status = "not_propagated"
            explanation = "None of the expected nameservers found"
            match = False

        return {
            "domain": domain,
            "resolved_ns": sorted(resolved_ns),
            "expected_ns": sorted(expected_ns),
            "match": match,
            "depth": depth,
            "status": status,
            "explanation": explanation
        }

    except Exception as e:
        return {
            "domain": domain,
            "resolved_ns": [],
            "expected_ns": sorted(expected_ns),
            "match": False,
            "depth": None,
            "status": "error",
            "explanation": f"Error occurred during NS propagation check: {str(e)}"
        }
