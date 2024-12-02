import dns.resolver
import dns.query
import dns.zone
import socket
from flask import jsonify


def dns_recon(domain):
    """Perform DNS reconnaissance on a given domain."""
    results = {"domain": domain, "records": {}, "zone_transfer": False, "subdomains": []}

    try:
        # Retrieve DNS records
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results["records"][record_type] = [answer.to_text() for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                results["records"][record_type] = []

        # Check for zone transfer
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_ip = socket.gethostbyname(str(ns.target))
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
                if zone:
                    results["zone_transfer"] = True
                    results["records"]["zone"] = {n.to_text(): str(zone[n]) for n in zone.nodes.keys()}
                    break
        except Exception:
            results["zone_transfer"] = False

        # Subdomain enumeration
        subdomain_wordlist = ['www', 'mail', 'ftp', 'test', 'dev', 'api', 'staging']
        for subdomain in subdomain_wordlist:
            subdomain_full = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(subdomain_full, 'A')
                results["subdomains"].append({
                    "subdomain": subdomain_full,
                    "records": [answer.to_text() for answer in answers]
                })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue

    except Exception as e:
        return jsonify({"error": f"An error occurred during DNS reconnaissance: {str(e)}"}), 500

    return jsonify({"message": "DNS reconnaissance completed.", "results": results}), 200
