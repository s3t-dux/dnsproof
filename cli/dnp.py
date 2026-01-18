import click
import os
import httpx

API_URL = os.getenv("DNSPROOF_API_URL", "http://localhost:8000")
API_PASSWORD = os.getenv("DNSPROOF_PASSWORD", "")

HEADERS = {
    "Authorization": f"Bearer {API_PASSWORD}"
} if API_PASSWORD else {}

@click.group()
def cli():
    """dnp: DNSProof CLI"""
    pass


@cli.command()
@click.option('--domain', required=True)
@click.option('--type', 'rtype', required=True)
@click.option('--name', required=True)
@click.option('--value', required=True)
@click.option('--ttl', default=3600, show_default=True)
def add(domain, rtype, name, value, ttl):
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
    click.echo(r.json())


@cli.command()
@click.option('--domain', required=True)
def list(domain):
    "List DNS records (raw JSON output)"
    try:
        r = httpx.get(f"{API_URL}/api/logs?limit=100", headers=HEADERS)
        records = r.json()
        domain_records = [rec for rec in records if rec['domain'] == domain]
        for rec in domain_records:
            click.echo(f"{rec['record_type']} {rec['record_name']} {rec['record_value']} (id={rec['id']})")
    except Exception as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.option('--domain', required=True)
@click.option('--record-id', required=True)
@click.option('--value', required=True)
def edit(domain, record_id, value):
    "Edit a DNS record (value only)"
    # In production, you should fetch current record from the zone file
    # For now, just update value only and keep others constant (mocked)
    record = {
        "type": "A",  # should be dynamic
        "name": "www", # should be dynamic
        "value": value,
        "ttl": 3600
    }
    payload = {
        "domain": domain,
        "edits": [{
            "record_id": record_id,
            "record": record
        }]
    }
    r = httpx.put(f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
    click.echo(r.json())


@cli.command()
@click.option('--domain', required=True)
@click.option('--record-id', required=True)
def delete(domain, record_id):
    "Delete a DNS record"
    payload = {
        "domain": domain,
        "record_ids": [record_id]
    }
    r = httpx.request("DELETE", f"{API_URL}/api/dns/records", json=payload, headers=HEADERS)
    click.echo(r.json())


@cli.command()
@click.option('--domain', required=True)
def dnssec_status(domain):
    "Check DNSSEC status for a domain"
    r = httpx.get(f"{API_URL}/api/dnssec/status/{domain}", headers=HEADERS)
    click.echo(r.json())


@cli.command()
@click.option('--domain', required=True)
def dnssec_enable(domain):
    "Enable DNSSEC for a domain"
    r = httpx.post(f"{API_URL}/api/dnssec/enable/{domain}", headers=HEADERS)
    click.echo(r.json())


@cli.command()
@click.option('--domain', required=True)
def dnssec_disable(domain):
    "Disable DNSSEC for a domain"
    r = httpx.post(f"{API_URL}/api/dnssec/disable/{domain}", headers=HEADERS)
    click.echo(r.json())


@cli.command()
@click.option('--limit', default=10, show_default=True)
def logs(limit):
    "View recent DNS change logs"
    r = httpx.get(f"{API_URL}/api/logs?limit={limit}", headers=HEADERS)
    for entry in r.json():
        click.echo(f"{entry['created_at']} | {entry['action']} {entry['record_type']} {entry['record_name']} -> {entry['record_value']}")


if __name__ == '__main__':
    cli()
