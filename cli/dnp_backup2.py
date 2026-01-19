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
    r = httpx.post(f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def list(as_json, domain):
    "List DNS records (raw JSON output)"
    try:
        r = httpx.get(f"{API_URL}/api/logs?limit=100", headers=HEADERS)
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
@json_option()
@click.option('--domain', required=True)
@click.option('--type', 'rtype', required=True)
@click.option('--old-name', required=True)
@click.option('--old-value', required=True)
@click.option('--new-name', required=True)
@click.option('--new-value', required=True)
@click.option('--new-ttl', type=int, default=None)
def edit(as_json, domain, rtype, old_name, old_value, new_name, new_value, new_ttl):
    "Edit a DNS record (lookup by old type+name+value, update name/value/ttl)"
    try:
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

        record_id = generate_record_id(candidates[0])

        updated_record = {
            "type": rtype,
            "name": new_name,
            "value": new_value,
        }
        if new_ttl is not None:
            updated_record["ttl"] = new_ttl

        payload = {
            "domain": domain,
            "edits": [{
                "record_id": record_id,
                "record": updated_record
            }]
        }

        r = httpx.put(f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
        print_output(r, as_json)

    except Exception as e:
        click.echo(f"Error: {e}")


@cli.command()
@json_option()
@click.option('--domain', required=True)
@click.option('--record-id', required=True)
def delete(as_json, domain, record_id):
    "Delete a DNS record"
    payload = {
        "domain": domain,
        "record_ids": [record_id]
    }
    r = httpx.request("DELETE", f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_status(as_json, domain):
    "Check DNSSEC status for a domain"
    r = httpx.get(f"{API_URL}/api/dnssec/status/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_enable(as_json, domain):
    "Enable DNSSEC for a domain"
    r = httpx.post(f"{API_URL}/api/dnssec/enable/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_disable(as_json, domain):
    "Disable DNSSEC for a domain"
    r = httpx.post(f"{API_URL}/api/dnssec/disable/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_rotate(as_json, domain):
    "Rotate DNSSEC keys for a domain"
    r = httpx.post(f"{API_URL}/api/dnssec/rotate/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_rotate_zsk(as_json, domain):
    "Rotate DNSSEC ZSK for a domain"
    r = httpx.post(f"{API_URL}/api/dnssec/rotate/zsk/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--domain', required=True)
def dnssec_resign(as_json, domain):
    "Re-sign the DNS zone for a domain"
    r = httpx.post(f"{API_URL}/api/dnssec/resign/{domain}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.argument('state', type=click.Choice(['on', 'off']))
def dnssec_auto_resign(as_json, state):
    "Toggle automatic DNSSEC re-signing (on/off)"
    r = httpx.post(f"{API_URL}/api/dnssec/auto_resign/{state}", headers=HEADERS)
    print_output(r, as_json)


@cli.command()
@json_option()
@click.option('--limit', default=10, show_default=True)
def logs(as_json, limit):
    "View recent DNS change logs"
    r = httpx.get(f"{API_URL}/api/logs?limit={limit}", headers=HEADERS)
    if as_json:
        print_output(r, as_json)
    else:
        for entry in r.json():
            click.echo(f"{entry['created_at']} | {entry['action']} {entry['record_type']} {entry['record_name']} -> {entry['record_value']}")


if __name__ == '__main__':
    cli()
