import click
import os
import httpx
import json

API_URL = os.getenv("DNSPROOF_API_URL", "http://localhost:8000")
API_PASSWORD = os.getenv("DNSPROOF_PASSWORD", "")

HEADERS = {
    "Authorization": f"Bearer {API_PASSWORD}"
} if API_PASSWORD else {}

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1] / "app"))

from config import JSON_DIR
from utils.zone_json import load_zone_json, generate_record_id

def api_call(method, *args, **kwargs):
    """
    Wrapper for all HTTP requests in DNSProof CLI.
    Supports all httpx methods (get, post, request, etc.).
    Gracefully handles 401, network errors, etc.
    """
    try:
        r = method(*args, **kwargs)
        r.raise_for_status()
        return r
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            click.echo("[ERROR] Unauthorized: Please set DNSPROOF_PASSWORD or check your credentials.")
        else:
            click.echo(f"[ERROR] HTTP error {e.response.status_code}: {e.response.text}")
        raise click.Abort()
    except httpx.RequestError as e:
        click.echo(f"[ERROR] Network error: {e}")
        raise click.Abort()

def json_option():
    return click.option("--json", "-j", "as_json", is_flag=True, help="Output raw JSON")


def print_output(response, as_json):
    if as_json:
        click.echo(json.dumps(response.json(), indent=2))
    else:
        click.echo(response.json())


@click.group()
def cli():
    """dnp: DNSProof CLI"""
    pass


@cli.command()
@json_option()
@click.option('--domain', required=True)
@click.option('--type', 'rtype', required=True)
@click.option('--name', required=True)
@click.option('--value', required=True)
@click.option('--ttl', default=3600, show_default=True)
def add(as_json, domain, rtype, name, value, ttl):
    "Add a DNS record"
    payload = {
        "domain": domain,
        "records": [{
            "type": rtype,
            "name": name,
            "value": value,
            "ttl": ttl
        }]
    }
    #r = httpx.post(f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
    r = api_call(httpx.post, f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def list(as_json, domain):
    "List DNS records (raw JSON output)"
    try:
        #r = httpx.get(f"{API_URL}/api/logs?limit=100", headers=HEADERS)
        r = api_call(httpx.get, f"{API_URL}/api/logs?limit=100", headers=HEADERS)
        if as_json:
            print_output(r, as_json)
        else:
            records = r.json()
            domain_records = [rec for rec in records if rec['domain'] == domain]
            for rec in domain_records:
                click.echo(f"{rec['record_type']} {rec['record_name']} {rec['record_value']} (id={rec['id']})")
    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@click.option('--type', 'rtype', required=True, help='Record type (e.g., A, TXT, MX)')
@click.option('--name', required=True, help='Record name (e.g., @, www)')
@click.option('--value', required=True, help='Record value (e.g., 1.2.3.4, \"hello\")')
def record_id(rtype, name, value):
    """Compute the record_id for a given type+name+value"""
    try:
        record = {
            "type": rtype,
            "name": name,
            "value": value
        }
        rid = generate_record_id(record)
        click.echo(rid)
    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@json_option()
@click.option('--domain', required=True)
@click.option('--record-id', required=False)
@click.option('--type', 'rtype', required=False)
@click.option('--old-name', required=False)
@click.option('--old-value', required=False)
@click.option('--new-name', required=True)
@click.option('--new-value', required=True)
@click.option('--new-ttl', type=int, default=None)
def edit(as_json, domain, record_id, rtype, old_name, old_value, new_name, new_value, new_ttl):
    """Edit a DNS record using record-id OR type+old-name+old-value"""
    try:
        if record_id:
            computed_id = record_id
        else:
            if not (rtype and old_name and old_value):
                raise click.UsageError("Either --record-id OR all of --type, --old-name, and --old-value must be provided.")

            zone_data = load_zone_json(domain)
            records = zone_data.get("records", [])
            candidates = [r for r in records if r["type"] == rtype and r["name"] == old_name and r["value"] == old_value]

            if len(candidates) == 0:
                click.echo("No matching record found.")
                return
            elif len(candidates) > 1:
                click.echo("Multiple matching records found. Please refine.")
                for r in candidates:
                    click.echo(f"Value: {r['value']} | TTL: {r.get('ttl', 3600)}")
                return

            computed_id = generate_record_id(candidates[0])

        updated_record = {
            "type": rtype if rtype else candidates[0]['type'],
            "name": new_name,
            "value": new_value,
        }
        if new_ttl is not None:
            updated_record["ttl"] = new_ttl

        payload = {
            "domain": domain,
            "edits": [{
                "record_id": computed_id,
                "record": updated_record
            }]
        }

        #r = httpx.put(f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
        r = api_call(httpx.put, f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
        print_output(r, as_json)

    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@json_option()
@click.option('--domain', required=True)
@click.option('--record-id', required=False)
@click.option('--type', 'rtype', required=False)
@click.option('--name', required=False)
@click.option('--value', required=False)
def delete(as_json, domain, record_id, rtype, name, value):
    "Delete a DNS record by record_id or type+name+value"
    try:
        if record_id:
            record_ids = [record_id]
        else:
            if not (rtype and name and value):
                raise click.UsageError("Either --record-id or all of --type, --name, and --value must be provided.")

            zone_data = load_zone_json(domain)
            records = zone_data.get("records", [])
            match = [r for r in records if r["type"] == rtype and r["name"] == name and r["value"] == value]

            if not match:
                click.echo("No matching record found.")
                return
            if len(match) > 1:
                click.echo("Multiple matching records found. Please refine your query.")
                for r in match:
                    click.echo(json.dumps(r, indent=2))
                return

            record_ids = [generate_record_id(match[0])]

        payload = {
            "domain": domain,
            "record_ids": record_ids
        }
        #r = httpx.request("DELETE", f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
        r = api_call(
            httpx.request,
            "DELETE",
            f"{API_URL}/api/dns/records",
            json=payload,
            headers=HEADERS
        )
        print_output(r, as_json)

    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@click.option('--domain', required=True)
@click.option('--output', type=click.Path(writable=True), default=None, help="Output file path. Defaults to stdout")
def dump_zone(domain, output):
    """Fetch and dump the zone JSON file from local disk"""
    try:
        zone_json = load_zone_json(domain)
        if output:
            with open(output, "w") as f:
                json.dump(zone_json, f, indent=2)
            click.echo(f"Zone JSON for '{domain}' written to {output}")
        else:
            click.echo(json.dumps(zone_json, indent=2))
    except Exception as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.option('--domain', required=True)
@click.option('--yes', is_flag=True, help="Bypass confirmation prompt")
@json_option()
def push_zone(as_json, domain, yes):
    """Send the local zone JSON to the API /agent for DNS deployment"""
    if not yes:
        click.echo("Warning: This zone push bypasses DNS change log and cryptographic signing.")
        if not click.confirm("Are you sure you want to push this zone?"):
            click.echo("Aborted.")
            return
    try:
        zone_json = load_zone_json(domain)
        #r = httpx.post(f"{API_URL}/api/dns/push", json=zone_json, headers=HEADERS)
        r = api_call(httpx.post, f"{API_URL}/api/dns/push", json=zone_json, headers=HEADERS)
        print_output(r, as_json)
    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_status(as_json, domain):
    "Check DNSSEC status for a domain"
    #r = httpx.get(f"{API_URL}/api/dnssec/status/{domain}", headers=HEADERS)
    r = api_call(httpx.get, f"{API_URL}/api/dnssec/status/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_enable(as_json, domain):
    "Enable DNSSEC for a domain"
    #r = httpx.post(f"{API_URL}/api/dnssec/enable/{domain}", headers=HEADERS)
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/enable/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_disable(as_json, domain):
    "Disable DNSSEC for a domain"
    #r = httpx.post(f"{API_URL}/api/dnssec/disable/{domain}", headers=HEADERS)
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/disable/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_rotate(as_json, domain):
    "Rotate DNSSEC keys for a domain"
    #r = httpx.post(f"{API_URL}/api/dnssec/rotate/{domain}", headers=HEADERS)
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/rotate/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_rotate_zsk(as_json, domain):
    "Rotate DNSSEC ZSK for a domain"
    #r = httpx.post(f"{API_URL}/api/dnssec/rotate/zsk/{domain}", headers=HEADERS)
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/rotate/zsk/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_resign(as_json, domain):
    "Re-sign the DNS zone for a domain"
    #r = httpx.post(f"{API_URL}/api/dnssec/resign/{domain}", headers=HEADERS)
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/resign/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.argument('state', type=click.Choice(['on', 'off']))
def dnssec_auto_resign(as_json, state):
    "Toggle automatic DNSSEC re-signing (on/off)"
    #r = httpx.post(f"{API_URL}/api/dnssec/auto_resign/{state}", headers=HEADERS)
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/auto_resign/{state}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--limit', default=10, show_default=True)
def logs(as_json, limit):
    "View recent DNS change logs"
    #r = httpx.get(f"{API_URL}/api/logs?limit={limit}", headers=HEADERS)
    r = api_call(httpx.get, f"{API_URL}/api/logs?limit={limit}", headers=HEADERS)
    if as_json:
        print_output(r, as_json)
    else:
        for entry in r.json():
            click.echo(f"{entry['created_at']} | {entry['action']} {entry['record_type']} {entry['record_name']} -> {entry['record_value']}")


if __name__ == '__main__':
    cli()
