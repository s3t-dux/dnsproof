import click
import os
import httpx
import json
import hashlib
import re
import subprocess
import shutil
import tempfile
import yaml
import getpass
from pathlib import Path
from functools import wraps

API_URL = os.getenv("DNSPROOF_API_URL", "http://localhost:8000")
API_PASSWORD = os.getenv("DNSPROOF_PASSWORD", "")

AGENT_PATTERN = re.compile(r"^\d+\.\d+\.\d+\.\d+\s+agent\.ns\d+\.\S+", re.IGNORECASE)
WINDOWS_HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
UNIX_HOSTS = "/etc/hosts"

# Global CLI context
class DNPContext:
    def __init__(self):
        self.api_url = API_URL
        self.api_password = None

pass_dnp = click.make_pass_decorator(DNPContext, ensure=True)


def generate_record_id(record: dict) -> str:
    """Generate a stable ID for a DNS record based on its type/name/value/priority/ttl."""
    content = json.dumps({
        "type": record["type"],
        "name": record["name"],
        "value": record["value"],
        "priority": record.get("priority"),
        "port": record.get("port"),
        "target": record.get("target"),
        "ttl": record.get("ttl", 3600),
    }, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()

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

def make_headers(ctx):
    return {"Authorization": f"Bearer {ctx.api_password}"} if ctx.api_password else {}

def requires_auth(fn):
    @wraps(fn)
    @pass_dnp
    def wrapper(ctx, *args, **kwargs):
        if not ctx.api_password:
            ctx.api_password = getpass.getpass("Enter DNSProof password: ")
        return fn(ctx, *args, **kwargs)
    return wrapper

@click.group()
@click.option('--api-url', default=None, help="Override DNSProof API URL (default: http://localhost:8000)")
@click.option('--password', default=None, help="DNSProof API password")
@pass_dnp
def cli(ctx, api_url, password):
    """dnp: DNSProof CLI"""
    ctx.api_url = api_url or os.getenv("DNSPROOF_API_URL", API_URL)
    ctx.api_password = password or os.getenv("DNSPROOF_PASSWORD")

@click.group()
def signing():
    """Signing key lifecycle commands."""
    pass

cli.add_command(signing)

@cli.command('records')
@json_option()
@click.option('--domain', '-d', required=True, help="Domain name to query")
@click.option('--type', 'rtype', default=None, help="Filter by record type (e.g. A, TXT, MX)")
@requires_auth
def records(ctx, as_json, domain, rtype):
    """Get current DNS records from zone file"""
    try:
        normalized_domain = domain.strip().lower()

        url = f"{API_URL}/api/dns/records?domain={normalized_domain}"
        r = api_call(httpx.get, url, headers=make_headers(ctx))
        data = r.json()

        if rtype:
            records = [
                rec for rec in data["records"]
                if rec["type"].upper() == rtype.upper()
            ]
        else:
            records = data["records"]

        if as_json:
            click.echo(json.dumps({
                "domain": data["domain"],
                "record_count": len(records),
                "records": records
            }, indent=2))
            return

        click.echo(f"Domain: {data['domain']}")
        click.echo(f"Record Count: {len(records)}")
        click.echo("-" * 50)

        for rec in records:
            ttl = f" TTL={rec['ttl']}" if rec.get("ttl") else ""
            pri = f" PRI={rec['priority']}" if rec.get("priority") else ""
            click.echo(
                f"[{rec['record_id'][:8]}...] "
                f"{rec['type']} {rec['name']} -> {rec['value']}{ttl}{pri}"
            )

    except Exception as e:
        click.echo(f"[ERROR] Failed to fetch records: {e}")

@cli.command('add')
@json_option()
@click.option('--domain', '-d', required=True)
@click.option('--type', 'rtype', required=True)
@click.option('--name', required=True)
@click.option('--value', required=True)
@click.option('--ttl', default=3600, show_default=True)
@requires_auth
def add_record(ctx, as_json, domain, rtype, name, value, ttl):
    """Add a DNS record"""

    normalized_domain = domain.strip().lower()

    payload = {
        "domain": normalized_domain,
        "records": [{
            "type": rtype,
            "name": name,
            "value": value,
            "ttl": ttl
        }]
    }
    r = api_call(httpx.post, f"{API_URL}/api/dns/records", json=payload, headers=make_headers(ctx))
    print_output(r, as_json)

@cli.command('record-id')
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

@cli.command('edit')
@json_option()
@click.option('--domain', '-d', required=True)
@click.option('--record-id', required=False)
@click.option('--type', 'rtype', required=False)
@click.option('--old-name', required=False)
@click.option('--old-value', required=False)
@click.option('--new-name', required=True)
@click.option('--new-value', required=True)
@click.option('--new-ttl', type=int, default=None)
@requires_auth
def edit_record(ctx, as_json, domain, record_id, rtype, old_name, old_value, new_name, new_value, new_ttl):
    """Edit a DNS record using record-id OR type+old-name+old-value"""
    try:
        if not record_id and not (rtype and old_name and old_value):
            raise click.UsageError("Either --record-id OR all of --type, --old-name, and --old-value must be provided.")

        normalized_domain = domain.strip().lower()

        # Compose new record (after edit)
        new_record = {
            "type": rtype if rtype else "TXT",  # Default to TXT if not specified
            "name": new_name,
            "value": new_value
        }
        if new_ttl is not None:
            new_record["ttl"] = new_ttl

        # Build edit payload
        if record_id:
            edit_payload = {
                "record_id": record_id,
                "new": new_record
            }
        else:
            old_record = {
                "type": rtype,
                "name": old_name,
                "value": old_value
            }
            edit_payload = {
                "old": old_record,
                "new": new_record
            }

        payload = {
            "domain": normalized_domain,
            "edits": [edit_payload]
        }

        r = api_call(httpx.put, f"{API_URL}/api/dns/records", json=payload, headers=make_headers(ctx))
        print_output(r, as_json)

    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command('delete')
@json_option()
@click.option('--domain', '-d', required=True)
@click.option('--record-id', required=False)
@click.option('--type', 'rtype', required=False)
@click.option('--name', required=False)
@click.option('--value', required=False)
@requires_auth
def delete_record(ctx, as_json, domain, record_id, rtype, name, value):
    """Delete a DNS record by record-id OR type+name+value"""
    try:
        if not record_id and not (rtype and name and value):
            raise click.UsageError(
                "Either --record-id OR all of --type, --name, and --value must be provided."
            )

        normalized_domain = domain.strip().lower()

        # Backend resolves identity
        if record_id:
            payload = {
                "domain": normalized_domain,
                "record_ids": [record_id]
            }
        else:
            payload = {
                "domain": normalized_domain,
                "records": [{
                    "type": rtype,
                    "name": name,
                    "value": value
                }]
            }

        r = api_call(
            httpx.request,
            "DELETE",
            f"{API_URL}/api/dns/records",
            json=payload,
            headers=make_headers(ctx)
        )
        print_output(r, as_json)

    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command('dump-zone')
@click.option('--domain', '-d', required=True)
@click.option('--output', type=click.Path(writable=True), default=None, help="Output file path. Defaults to stdout")
@requires_auth
def dump_zone(ctx, domain, output):
    """Fetch and dump the canonical zone JSON file from the app backend."""
    try:
        normalized_domain = domain.strip().lower()

        r = api_call(
            httpx.get,
            f"{API_URL}/api/dns/dump",
            headers=make_headers(ctx),
            params={"domain": normalized_domain}
        )

        zone_json = r.json()["zone_json"]

        if output:
            with open(output, "w") as f:
                json.dump(zone_json, f, indent=2)
            click.echo(f"[DUMP-ZONE] Zone JSON for '{normalized_domain}' written to {output}")
        else:
            click.echo(json.dumps(zone_json, indent=2))

    except Exception as e:
        click.echo(f"[ERROR] Failed to dump zone: {e}")
        raise click.Abort()

@cli.command('push-zone')
@click.option('--zone-json', '-z', type=click.Path(exists=True), required=True, help="Path to zone JSON file (e.g., ./dnsproof.org.json)")
@json_option()
@requires_auth
def push_zone(ctx, as_json, zone_json):
    """Send the local zone JSON to the agent API for DNS deployment"""
    import json

    try:
        with open(zone_json, "r") as f:
            payload = json.load(f)

        if "domain" not in payload or "records" not in payload:
            raise ValueError("Zone JSON file must include 'domain' and 'records' keys.")

        r = api_call(httpx.post, f"{API_URL}/api/dns/push", json=payload, headers=make_headers(ctx))
        print_output(r, as_json)
    except Exception as e:
        click.echo(f"Error: {e}")

@cli.command("export-domain")
@click.option('--domain', '-d', required=True, help="Domain to export")
@click.option('--output', '-o', type=click.Path(), required=True, help="Directory to write exported files into")
@requires_auth
def export_domain(ctx, domain, output):
    """
    Export a portable domain bundle:
    - stored dns_config.yaml from backend
    - canonical zone JSON from backend
    """
    try:
        normalized_domain = domain.strip().lower()
        out_dir = Path(output).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        config_path = out_dir / "dns_config.yaml"
        zone_path = out_dir / f"{normalized_domain}.json"

        # Fetch stored config
        config_resp = api_call(
            httpx.get,
            f"{API_URL}/api/dns/get-config",
            headers=make_headers(ctx),
            params={"domain": normalized_domain}
        )
        config_result = config_resp.json()
        config_yaml = config_result["config_yaml"]

        with open(config_path, "w") as f:
            f.write(config_yaml)

        # Fetch canonical zone
        zone_resp = api_call(
            httpx.get,
            f"{API_URL}/api/dns/dump",
            headers=make_headers(ctx),
            params={"domain": normalized_domain}
        )
        zone_result = zone_resp.json()
        zone_json = zone_result["zone_json"]

        with open(zone_path, "w") as f:
            json.dump(zone_json, f, indent=2)

        click.echo(f"[EXPORT] Domain: {normalized_domain}")
        click.echo(f"[EXPORT] Config: {config_path}")
        click.echo(f"[EXPORT] Zone:   {zone_path}")
        click.echo("[EXPORT] Portable domain bundle written successfully.")

    except Exception as e:
        click.echo(f"[ERROR] Failed to export domain: {e}")
        raise click.Abort()
    
@cli.command("import-domain")
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    required=True,
    help="Path to dns_config.yaml"
)
@click.option(
    "--zone", "-z",
    type=click.Path(exists=True),
    required=True,
    help="Path to exported zone JSON file"
)
@click.option(
    "--force", "-f",
    is_flag=True,
    help="Skip confirmation prompt when overwriting an existing domain config/zone"
)
@requires_auth
def import_domain(ctx, config, zone, force):
    """
    Import a portable domain bundle into DNSProof.

    Behavior:
    - If the domain is not registered yet, register it with the imported config.
    - If the domain already exists, update its stored config with the imported config.
    - Push the imported canonical zone JSON to the backend/agents.
    """
    import yaml
    import json
    from pathlib import Path

    try:
        config_path = Path(config).expanduser().resolve()
        zone_path = Path(zone).expanduser().resolve()

        # -----------------------------
        # 1. Load and validate config
        # -----------------------------
        with open(config_path, "r") as f:
            config_text = f.read()

        config_data = yaml.safe_load(config_text) or {}
        config_domain = config_data.get("domain")

        if not config_domain or not isinstance(config_domain, str):
            click.echo("[ERROR] 'domain' field missing from config YAML.")
            raise click.Abort()

        normalized_config_domain = config_domain.strip().lower()

        # -----------------------------
        # 2. Load and validate zone JSON
        # -----------------------------
        with open(zone_path, "r") as f:
            zone_json = json.load(f)

        if not isinstance(zone_json, dict):
            click.echo("[ERROR] Zone JSON must be a JSON object.")
            raise click.Abort()

        zone_domain = zone_json.get("domain")
        records = zone_json.get("records")

        if not zone_domain or not isinstance(zone_domain, str):
            click.echo("[ERROR] Zone JSON missing 'domain' field.")
            raise click.Abort()

        if not isinstance(records, list):
            click.echo("[ERROR] Zone JSON missing 'records' list.")
            raise click.Abort()

        normalized_zone_domain = zone_domain.strip().lower()

        if normalized_config_domain != normalized_zone_domain:
            click.echo("[ERROR] Domain mismatch between config and zone bundle.")
            click.echo(f"        Config domain: {normalized_config_domain}")
            click.echo(f"        Zone domain:   {normalized_zone_domain}")
            raise click.Abort()

        # Normalize zone payload before push
        zone_json["domain"] = normalized_zone_domain

        # -----------------------------
        # 3. Attempt registration
        # -----------------------------
        register_payload = {
            "domain": normalized_config_domain,
            "config_yaml": config_text
        }

        register_resp = api_call(
            httpx.post,
            f"{API_URL}/api/dns/register-domain",
            json=register_payload,
            headers=make_headers(ctx)
        )

        register_result = register_resp.json()
        register_status = register_result.get("status")

        if register_status not in {"registered", "exists"}:
            click.echo(f"[ERROR] Unexpected registration response: {register_result}")
            raise click.Abort()

        # -----------------------------
        # 4. Confirm overwrite if exists
        # -----------------------------
        if register_status == "exists" and not force:
            click.echo("")
            click.echo(f"[WARNING] Domain '{normalized_config_domain}' already exists in the backend.")
            click.echo("This will:")
            click.echo("  • Update the stored dns_config.yaml")
            click.echo("  • Push the imported canonical zone")
            click.echo("")
            if not click.confirm("Proceed?", default=False):
                click.echo("Aborted.")
                return

        # -----------------------------
        # 5. If exists, sync config
        # -----------------------------
        config_status_label = "stored"

        if register_status == "exists":
            set_config_payload = {
                "domain": normalized_config_domain,
                "config_yaml": config_text
            }

            set_config_resp = api_call(
                httpx.post,
                f"{API_URL}/api/dns/set-config",
                json=set_config_payload,
                headers=make_headers(ctx)
            )

            set_config_result = set_config_resp.json()
            set_config_status = set_config_result.get("status")

            if set_config_status not in {"updated", "stored"}:
                click.echo(f"[ERROR] Unexpected set-config response: {set_config_result}")
                raise click.Abort()

            config_status_label = set_config_status

        # -----------------------------
        # 6. Push zone
        # -----------------------------
        push_resp = api_call(
            httpx.post,
            f"{API_URL}/api/dns/push",
            json=zone_json,
            headers=make_headers(ctx)
        )

        push_result = push_resp.json()

        # -----------------------------
        # 7. Success output
        # -----------------------------
        click.echo(f"[IMPORT] Domain:        {normalized_config_domain}")
        click.echo(f"[IMPORT] Registration:  {register_status}")
        click.echo(f"[IMPORT] Config:        {config_status_label}")
        click.echo(f"[IMPORT] Zone file:     {zone_path}")
        click.echo(f"[IMPORT] Record count:  {len(records)}")
        click.echo("[IMPORT] Zone pushed successfully.")
        click.echo("[IMPORT] Portable domain bundle imported successfully.")

    except click.Abort:
        raise
    except Exception as e:
        click.echo(f"[ERROR] Failed to import domain: {e}")
        raise click.Abort()
    
@cli.command('dnssec-status')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_status(ctx, as_json, domain):
    "Check DNSSEC status for a domain"
    normalized_domain = domain.strip().lower()
    r = api_call(httpx.get, f"{API_URL}/api/dnssec/status/{normalized_domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-enable')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_enable(ctx, as_json, domain):
    "Enable DNSSEC for a domain"
    normalized_domain = domain.strip().lower()
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/enable/{normalized_domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-disable')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_disable(ctx, as_json, domain):
    "Disable DNSSEC for a domain"
    normalized_domain = domain.strip().lower()
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/disable/{normalized_domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-rotate')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_rotate(ctx, as_json, domain):
    "Rotate DNSSEC keys for a domain"
    normalized_domain = domain.strip().lower()
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/rotate/{normalized_domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-rotate-zsk')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_rotate_zsk(ctx, as_json, domain):
    "Rotate DNSSEC ZSK for a domain"
    normalized_domain = domain.strip().lower()
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/rotate/zsk/{normalized_domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-resign')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_resign(ctx, as_json, domain):
    "Re-sign the DNS zone for a domain"
    normalized_domain = domain.strip().lower()
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/resign/{normalized_domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-auto-resign')
@json_option()
@click.option('--domain', '-d', required=True)
@click.option('--state', '-s', type=click.Choice(['on', 'off']), required=True)
@requires_auth
def dnssec_auto_resign(ctx, as_json, domain, state):
    """Toggle automatic DNSSEC re-signing (on/off) for a domain"""
    url = f"{API_URL}/api/dnssec/auto_resign/{domain}/{state}"
    r = api_call(httpx.post, url, headers=make_headers(ctx))
    print_output(r, as_json)

@cli.command('logs-dns')
@json_option()
@click.option('--domain', '-d', required=False)
@click.option('--limit', default=10, show_default=True)
@requires_auth
def logs_dns(ctx, as_json, domain, limit):
    "View recent DNS change logs"
    url = f"{API_URL}/api/logs/dns?limit={limit}"
    if domain:
        normalized_domain = domain.strip().lower()
        url += f"&domain={normalized_domain}"

    def extract_value(snapshot):
        if isinstance(snapshot, dict):
            return snapshot.get("value", "?")
        return "?"

    r = api_call(httpx.get, url, headers=make_headers(ctx))
    if as_json:
        print_output(r, as_json)
    else:
        for entry in r.json():
            ts = entry["created_at"]
            action = entry["action"]
            rtype = entry["record_type"]
            name = entry["record_name"]
            val = entry["record_value"]

            if action == "edit" and entry.get("old_snapshot"):
                old = json.loads(entry["old_snapshot"])
                old_val = extract_value(old)
                click.echo(f"{ts} | edit {rtype} {name} '{old_val}' -> '{val}'")
            else:
                click.echo(f"{ts} | {action} {rtype} {name} -> {val}")

@cli.command("logs-dnssec")
@json_option()
@click.option('--domain', '-d', required=False)
@click.option('--limit', default=10, show_default=True)
@requires_auth
def logs_dnssec(ctx, as_json, domain, limit):
    "View recent DNSSEC-related logs"
    url = f"{API_URL}/api/logs/dnssec?limit={limit}"
    if domain:
        normalized_domain = domain.strip().lower()
        url += f"&domain={normalized_domain}"

    r = api_call(httpx.get, url, headers=make_headers(ctx))

    if as_json:
        print_output(r, as_json)
    else:
        for entry in r.json():
            click.echo(f"{entry['created_at']} | {entry['action'].upper()} | domain={entry['domain']} | key_tag={entry.get('key_tag', '–')}")

@cli.command("logs-signing")
@json_option()
@click.option('--limit', default=10, show_default=True)
@requires_auth
def logs_signing(ctx, as_json, limit):
    "View logs of generated signing keys (DNS record or DNSSEC)"
    url = f"{API_URL}/api/logs/signing_keys?limit={limit}"

    r = api_call(httpx.get, url, headers=make_headers(ctx))

    if as_json:
        print_output(r, as_json)
    else:
        for entry in r.json():
            status = "revoked" if entry.get("revoked") else "active"
            click.echo(f"{entry['created_at']} | {entry['key_type']} | {entry['public_key'][:32]}... | {status}")

@cli.command("verify-log")
@json_option()
@click.option('--id', 'log_id', required=True, help="Log ID to verify")
@requires_auth
def verify_log(ctx, as_json, log_id):
    """Verify cryptographic signature of a DNS change log entry"""
    try:
        url = f"{API_URL}/api/logs/verify/{log_id}"
        r = api_call(httpx.get, url, headers=make_headers(ctx))
        data = r.json()

        if as_json:
            print_output(r, as_json)
            return

        status_str = "VALID" if data["verified"] else "INVALID"
        click.echo(f"VERIFICATION: {status_str}")
        click.echo(f"Log ID:        {log_id}")
        click.echo(f"Snapshot Hash: {data['snapshot_hash']}")
        click.echo(f"Signature:     {data['signature'][:40]}...")
        click.echo(f"Public Key:    {data['public_key'][:40]}...")
        click.echo(f"Message:       {data['message']}")

    except Exception as e:
        click.echo(f"[ERROR] Verification failed: {e}")

@cli.command("verify-log-offline")
@click.option("--file", type=click.Path(exists=True), required=True, help="Path to JSON log file (one record or list)")
def verify_log_offline(file):
    """Verify one or more DNS log entries from a local JSON file"""
    try:
        import base64
        from nacl.signing import VerifyKey

        with open(file, "r") as f:
            content = json.load(f)

        if isinstance(content, dict):
            entries = [content]
        elif isinstance(content, list):
            entries = content
        else:
            raise ValueError("Unsupported JSON format")

        passed = 0
        failed = 0

        for i, entry in enumerate(entries):
            try:
                snapshot_hash = entry["snapshot_hash"]
                signature = entry["signature"]
                public_key = entry["public_key"]

                hash_bytes = snapshot_hash.encode()
                sig_bytes = base64.b64decode(signature)
                pubkey_bytes = base64.b64decode(public_key)

                verify_key = VerifyKey(pubkey_bytes)
                verify_key.verify(hash_bytes, sig_bytes)

                click.echo(f"[{i+1}] VERIFICATION: VALID")
                click.echo(f"      Snapshot Hash: {snapshot_hash}")
                click.echo(f"      Signature:     {signature[:40]}...")
                click.echo(f"      Public Key:    {public_key[:40]}...")
                passed += 1

            except Exception as e:
                click.echo(f"[{i+1}] VERIFICATION: INVALID")
                click.echo(f"      Error: {e}")
                failed += 1

        click.echo("-" * 60)
        click.echo(f"Total Verified: {passed} ")
        click.echo(f"Total Failed:   {failed} ")

    except Exception as e:
        click.echo(f"[ERROR] Could not read or parse file: {e}")

@signing.command("active-key")
@json_option()
@requires_auth
def active_key(ctx, as_json):
    """
    Show the currently active (non-revoked) signing key metadata.

    Displays the active (non-revoked) signing key
    from KeyGenerationLog.
    """
    try:
        url = f"{API_URL}/api/signing/active-key"
        r = api_call(httpx.get, url, headers=make_headers(ctx))

        if as_json:
            print_output(r, as_json)
            return

        key = r.json()

        click.echo("")
        click.echo("Active Signing Key")
        click.echo("------------------")
        click.echo(f"ID          : {key.get('id')}")
        click.echo(f"Created     : {key.get('created_at')}")
        click.echo(f"Type        : {key.get('key_type')}")
        click.echo(f"Purpose     : {key.get('purpose')}")
        click.echo(f"Fingerprint : {key.get('fingerprint')}")
        click.echo(f"Public Key  : {key.get('public_key')}")
        click.echo(f"Key Path    : {key.get('key_path')}")
        click.echo("")

    except Exception as e:
        click.echo(f"[ERROR] Failed to fetch signing key: {e}")

@signing.command("keys")
@json_option()
@requires_auth
def signing_key(ctx, as_json):
    """
    Show signing key lifecycle.

    - In JSON mode: return the active key only.
    - In human mode: show active key + revoked history.
    """
    try:
        headers = make_headers(ctx)

        if as_json:
            # Preserve old behavior: just active key as JSON
            url = f"{API_URL}/api/signing/active-key"
            r = api_call(httpx.get, url, headers=headers)
            print_output(r, as_json)
            return

        # Human-readable: fetch full lifecycle
        url = f"{API_URL}/api/signing/keys"
        r = api_call(httpx.get, url, headers=headers)
        keys = r.json()

        if not keys:
            click.echo("No signing keys found.")
            return

        active = [k for k in keys if not k.get("revoked")]
        revoked = [k for k in keys if k.get("revoked")]

        if len(active) != 1:
            click.echo("[ERROR] Invariant violation: expected exactly one active key.")
            click.echo(f"Active candidates found: {len(active)}")
            # Optionally dump raw JSON for debugging:
            # click.echo(json.dumps(keys, indent=2))
            return

        ak = active[0]

        click.echo("")
        click.echo("Active Signing Key")
        click.echo("------------------")
        click.echo(f"ID          : {ak.get('id')}")
        click.echo(f"Created     : {ak.get('created_at')}")
        click.echo(f"Type        : {ak.get('key_type')}")
        click.echo(f"Purpose     : {ak.get('purpose')}")
        click.echo(f"Fingerprint : {ak.get('fingerprint')}")
        click.echo(f"Public Key  : {ak.get('public_key')}")
        click.echo(f"Key Path    : {ak.get('key_path')}")
        click.echo(f"Replaced By : {ak.get('replaced_by')}")
        click.echo("")

        if revoked:
            click.echo("Revoked Keys")
            click.echo("------------")
            for rk in revoked:
                click.echo(
                    f"- ID={rk.get('id')}, "
                    f"created={rk.get('created_at')}, "
                    f"revoked_at={rk.get('revoked_at')}, "
                    f"replaced_by={rk.get('replaced_by')}, "
                    f"fingerprint={rk.get('fingerprint')}"
                )
            click.echo("")

    except Exception as e:
        click.echo(f"[ERROR] Failed to fetch signing key lifecycle: {e}")

@signing.command("rotate")
@json_option()
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompt")
@requires_auth
def signing_rotate(ctx, force, as_json):
    """
    Rotate the DNS record signing key.

    This revokes the currently active signing key,
    generates a new Ed25519 key,
    and preserves a timestamped backup of the old key.

    This action is irreversible.
    """
    if not force:
        click.echo("")
        click.echo("WARNING: You are about to rotate the DNS signing key.")
        click.echo("This will:")
        click.echo("  • Revoke the currently active signing key")
        click.echo("  • Generate a new Ed25519 key")
        click.echo("  • Create a timestamped backup of the old key")
        click.echo("")
        click.echo("This action cannot be undone.")
        click.echo("")

        confirm = click.prompt("Proceed? (y/N)", default="N")

        if confirm.lower() != "y":
            click.echo("Aborted.")
            return

    try:
        url = f"{API_URL}/api/signing/rotate"
        r = api_call(httpx.post, url, headers=make_headers(ctx))
        
        data = r.json()

        if as_json:
            print_output(r, as_json)
            return

        click.echo("")
        click.echo("[SUCCESS] Signing key rotated successfully")
        click.echo(f"Old Key ID : {data.get('old_key_id')}")
        click.echo(f"New Key ID : {data.get('new_key_id')}")
        click.echo(f"Backup Path: {data.get('backup_path')}")
        click.echo("")

    except Exception as e:
        click.echo(f"[ERROR] Signing key rotation failed: {e}")

@cli.command('verify-ns')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def verify_ns(ctx, as_json, domain):
    "Query each agent directly for NS records"
    normalized_domain = domain.strip().lower()
    r = api_call(httpx.get, f"{API_URL}/api/ns/verify-ns/{normalized_domain}", headers=make_headers(ctx))
    print_output(r, as_json)

@cli.command('ns-propagation')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def ns_propagation(ctx, as_json, domain):
    """Check if NS records are fully propagated"""
    try:
        normalized_domain = domain.strip().lower()
        r = api_call(httpx.get, f"{API_URL}/api/ns/ns-propagation-status/{normalized_domain}", headers=make_headers(ctx), timeout=35.0)
        print_output(r, as_json)
    except httpx.RequestError as e:
        click.echo("[ERROR] Could not complete NS propagation check.")
        click.echo("Hint: Make sure your registrar has updated NS records pointing to the correct IPs.")
        click.echo(f"(details: {e})")
        raise click.Abort()
    except Exception as e:
        click.echo(f"[ERROR] Unexpected failure: {e}")
        raise click.Abort()

@cli.command("nameservers")
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def get_nameservers(ctx, as_json, domain):
    """List NS records configured in DNSProof config"""
    normalized_domain = domain.strip().lower()
    r = api_call(httpx.get, f"{API_URL}/api/ns/nameservers/{normalized_domain}", headers=make_headers(ctx))
    print_output(r, as_json)

@cli.command('ns-status')
@json_option()
@click.option('--domain', '-d', required=True, help="Domain to query for resolver health")
@requires_auth
def ns_status(ctx, as_json, domain):
    """Check CoreDNS/NSD status on all agent VMs for a given domain"""
    try:
        normalized_domain = domain.strip().lower()
        payload = {"domain": normalized_domain}
        r = api_call(
            httpx.post,
            f"{API_URL}/api/dns/nameserver-status",
            json=payload,
            headers=make_headers(ctx)
        )
        result = r.json()

        if as_json:
            click.echo(json.dumps(result, indent=2))
            return

        click.echo(f"Domain: {result['domain']}")
        click.echo(f"Overall Status: {'Healthy' if result['is_active'] else 'Issue Detected'}")
        click.echo(f"Details: {result['status_details']}")
        click.echo("-" * 40)

        for entry in result['results']:
            ip = entry["ip"]
            status = entry["status"]
            if status == "active":
                label = "[OK]"
            elif status == "inactive":
                label = "[DOWN]"
            elif status == "timeout":
                label = "[TIMEOUT]"
            else:
                label = "[ERROR]"

            click.echo(f"{label} {ip} - {status}")
            if entry.get("error"):
                click.echo(f"    Error: {entry['error']}")

    except Exception as e:
        click.echo(f"[ERROR] Failed to check nameserver status: {e}")

@cli.command('hostsync')
@json_option()
@click.option('--platform', '-p', required=True, type=click.Choice(['windows', 'unix']))
@click.option('--config', '-c', type=click.Path(exists=True), default="dns_config.yaml", show_default=True, help="Path to dns_config.yaml")
def hostsync(as_json, platform, config):
    """Update the local hosts file using dns_config.yaml"""
    try:
        cfg_path = Path(config)
        if not cfg_path.exists():
            raise FileNotFoundError(f"Missing dns_config.yaml at {cfg_path}")

        with open(cfg_path, 'r') as f:
            cfg = yaml.safe_load(f)

        domain = cfg["domain"]
        entries = [f"{ns['ip']} agent.{name}.{domain}" for name, ns in cfg["nameservers"].items() if "ip" in ns]

        hosts_path = WINDOWS_HOSTS if platform == "windows" else UNIX_HOSTS

        with open(hosts_path, 'r') as f:
            lines = f.readlines()

        filtered = [line for line in lines if not AGENT_PATTERN.match(line.strip())]
        updated = filtered + [entry + '\n' for entry in entries]

        # Backup first
        backup_path = hosts_path + ".bak"
        shutil.copy2(hosts_path, backup_path)

        if platform == "unix":
            tmpfile = tempfile.NamedTemporaryFile("w", delete=False)
            tmpfile.writelines(updated)
            tmpfile.close()
            subprocess.run(["sudo", "cp", tmpfile.name, hosts_path], check=True)
            Path(tmpfile.name).unlink()
        else:
            with open(hosts_path, 'w') as f:
                f.writelines(updated)

        click.echo(f"[INFO] {hosts_path} updated. Backup saved at {backup_path}")

    except Exception as e:
        click.echo(f"[ERROR] Failed to update hosts file: {e}")
        raise click.Abort()

@cli.command("install")
@click.option("--config", "-c", required=True, type=click.Path(exists=True), help="Path to dns_config.yaml")
@click.option("--agent-secret", "-s", required=True, help="Shared HMAC secret for agent authentication")
def install_nameservers(config, agent_secret):
    """
    Provision a nameserver VM using Python-based provisioner.
    """
    click.echo("[INFO] Starting nameserver provisioning via Python provisioner")
    click.echo(f"  Config:        {Path(config).resolve()}")
    click.echo(f"  Agent Secret:  (hidden)")
    click.echo("-" * 60)

    try:
        # Import locally to avoid import-time side effects
        from cli import provision

        # Call provisioner entrypoint
        provision.main(
            config_path=str(Path(config).resolve()),
            agent_secret=agent_secret,
        )

        click.echo("[SUCCESS] Nameserver provisioned successfully.")

    except PermissionError:
        click.echo("[FATAL] Permission denied. Did you forget to run with sudo?")
        raise click.Abort()

    except Exception as e:
        click.echo(f"[FATAL] Installation failed: {e}")
        raise click.Abort()

@cli.command("generate-config")
@click.option("--domain", "-d", required=True, help="Base domain (e.g., example.org)")
@click.option("--primary-ns", "-p", required=True, help="Primary nameserver name (e.g., ns1)")
@click.option("--ns", "-n", multiple=True, required=True, help="Nameserver entry in the format name:ip (e.g., ns1:1.2.3.4)")
@click.option("--output", "-o", default="dns_config.yaml", help="Output path for config file")
@click.option("--resolver", type=click.Choice(["nsd", "coredns"]), default="nsd", show_default=True, help="DNS resolver to use (nsd or coredns)")
@click.option("--tls-enabled", is_flag=True, default=False, help="Enable TLS communication with agents")
@click.option("--agent-cert-path-ns", default="/etc/ssl/dnsproof", show_default=True, help="Cert path on the nameserver")
@click.option("--agent-cert-path-app", default="../tls_cert", show_default=True, help="Cert path on the app backend")
def generate_config(domain, primary_ns, ns, output, resolver, tls_enabled, agent_cert_path_ns, agent_cert_path_app):
    """
    Generate a basic dns_config.yaml file using domain and nameserver info.
    """
    import yaml
    from pathlib import Path

    try:
        nameservers = {}
        for entry in ns:
            if ':' not in entry:
                raise click.BadParameter(f"Invalid --ns format: {entry}. Expected name:ip")
            name, ip = entry.split(":", 1)
            nameservers[name] = {"ip": ip}

        config = {
            "domain": domain.strip().lower(),
            "primary_ns": primary_ns.strip(),
            "nameservers": nameservers,
            "resolver": resolver,
            "tls_enabled": tls_enabled,
        }
        if tls_enabled:
            config["agent_cert_path_ns"] = agent_cert_path_ns
            config["agent_cert_path_app"] = agent_cert_path_app

        out_path = Path(output)
        if out_path.exists():
            click.echo(f"[WARNING] {output} already exists.")
            if not click.confirm("Overwrite it?"):
                click.echo("Aborted.")
                return

        with open(out_path, "w") as f:
            yaml.safe_dump(config, f, sort_keys=False)

        click.echo(f"[SUCCESS] Config written to {out_path}")

        if "Program Files/Git" in agent_cert_path_ns.replace("\\", "/"):
            click.echo("[WARN] Detected Git Bash path translation. You may want to use /c/srv/certs or C:\\srv\\certs to avoid surprises.")


    except Exception as e:
        click.echo(f"[ERROR] Failed to generate config: {e}")

@cli.command('generate-agent-secret')
@click.option('--output', '-o', default="agent.secret", type=click.Path(), help="File to save the generated secret")
@click.option('--show', is_flag=True, help="Also print the secret to stdout")
@click.option('--copy', is_flag=True, help="Copy the secret to clipboard (if pyperclip is installed)")
def generate_agent_secret(output, show, copy):
    """Generate a secure AGENT_SECRET for use in nameserver provisioning"""
    import secrets

    secret = secrets.token_hex(32)  # 64-char hex = 256-bit HMAC secret

    # Write to file
    path = Path(output).resolve()
    path.write_text(secret)
    click.echo(f"[SUCCESS] Agent secret written to: {path}")

    # Optionally show it
    if show:
        click.secho(f"[SECRET] {secret}", fg="yellow")

    # Optionally copy to clipboard
    if copy:
        try:
            import pyperclip
            pyperclip.copy(secret)
            click.echo("[INFO] Secret copied to clipboard.")
        except ImportError:
            click.secho("[WARNING] pyperclip not installed. Skipping clipboard copy.", fg="red")

@cli.command('init')
@click.option('--config', '-c', type=click.Path(exists=True), default='dns_config.yaml', help="Path to dns_config.yaml")
@click.option('--output', '-o', type=click.Path(), default=None, help="Path to save the generated zone JSON file")
@requires_auth
def init(ctx, config, output):
    """
    Initialize a vanilla JSON zone file with SOA, NS, and A records.
    Registers the domain with the app backend.
    """
    import yaml
    import json
    from pathlib import Path
    from datetime import datetime

    with open(config) as f:
        cfg = yaml.safe_load(f)

    domain = cfg["domain"]
    domain = domain.strip().lower() # normalize the domain name
    primary_ns = cfg["primary_ns"]
    nameservers = cfg["nameservers"]

    # Build SOA string: nsX.domain. admin.domain. <serial> ...
    soa_mname = f"{primary_ns}.{domain}."
    soa_rname = f"admin.{domain}."
    serial = datetime.utcnow().strftime("%Y%m%d01")  # e.g., 2026012601
    soa_value = f"{soa_mname} {soa_rname} {serial} 7200 1800 1209600 3600"

    records = [
        {
            "type": "SOA",
            "name": "@",
            "value": soa_value
        }
    ]

    # Add NS and A records for all nameservers
    for ns_name, ns_data in nameservers.items():
        fqdn = f"{ns_name}.{domain}."
        ip = ns_data["ip"]

        records.append({
            "type": "NS",
            "name": "@",
            "value": fqdn
        })
        records.append({
            "type": "A",
            "name": ns_name,
            "value": ip
        })

    # Optional TXT record
    records.append({
        "type": "TXT",
        "name": "@",
        "value": "dnsproof init",
        "ttl": 3600
    })

    zone_json = {
        "domain": domain,
        "records": records
    }

    # Determine output path
    if output:
        out_path = Path(output)
    else:
        out_path = Path(f"{domain}.json")

    if out_path.exists():
        click.echo(f"[WARNING] {domain}.json already exists at {out_path}")
        if not click.confirm("Overwrite it?"):
            click.echo("Aborted.")
            return

    try:
        # Save local JSON zone file
        with open(out_path, "w") as f:
            json.dump(zone_json, f, indent=2)
        click.echo(f"[INIT] Zone file initialized at: {out_path}")

        # Register domain with backend
        with open(config) as f:
            cfg_text = f.read()

        r = api_call(
            httpx.post,
            f"{API_URL}/api/dns/register-domain",
            json={"domain": domain, "config_yaml": cfg_text},
            headers=make_headers(ctx)
        )
        result = r.json()
        status = result.get("status")

        if status == "registered":
            click.echo(f"[REGISTER] Domain registered with backend: {domain}")
        elif status == "exists":
            click.echo(f"[REGISTER] Domain already registered: {domain}")
        else:
            click.echo(f"[REGISTER] Unknown registration response: {result}")
    except Exception as e:
        click.echo(f"[ERROR] Failed to initialize: {e}")

@cli.command("set-config")
@click.option('--file', '-f', type=click.Path(exists=True), required=True, help="Path to dns_config.yaml")
@requires_auth
def set_config(ctx, file):
    """Set or update DNS config YAML for a domain"""
    import yaml

    try:
        with open(file, "r") as f:
            config_text = f.read()
            config_data = yaml.safe_load(config_text)

        domain = config_data.get("domain")
        if not domain:
            click.echo("[ERROR] 'domain' field missing from config YAML")
            raise click.Abort()

        payload = {
            "domain": domain.strip().lower(),
            "config_yaml": config_text
        }

        r = api_call(
            httpx.post,
            f"{API_URL}/api/dns/set-config", 
            json=payload,
            headers=make_headers(ctx)
        )

        result = r.json()
        click.echo(f"[SET-CONFIG] Domain: {domain}")
        click.echo(f"[SET-CONFIG] Status: {result.get('status')}")
        if result.get("status") == "updated":
            click.echo("[SET-CONFIG] Config successfully stored.")
        else:
            click.echo("[SET-CONFIG] No config provided or update skipped.")

    except Exception as e:
        click.echo(f"[ERROR] Failed to set config: {e}")
        raise click.Abort()

@cli.command("get-config")
@click.option('--domain', '-d', required=True, help="Domain to fetch stored config for")
@click.option('--output', '-o', type=click.Path(writable=True), default=None, help="Optional path to save config file")
@requires_auth
def get_config(ctx, domain, output):
    """Fetch stored dns_config.yaml from backend DB"""
    try:
        normalized_domain = domain.strip().lower()
        r = api_call(
            httpx.get,
            f"{API_URL}/api/dns/get-config",
            headers=make_headers(ctx),
            params={"domain": normalized_domain}
        )
        result = r.json()
        yaml_text = result["config_yaml"]

        if output:
            with open(output, "w") as f:
                f.write(yaml_text)
            click.echo(f"[GET-CONFIG] Config for {normalized_domain} saved to {output}")
        else:
            click.echo(f"# Stored config for {normalized_domain} (last updated {result['updated_at']}):\n")
            click.echo(yaml_text)

    except Exception as e:
        click.echo(f"[ERROR] Failed to get config: {e}")
        raise click.Abort()

@cli.command('get-domains')
@json_option()
@requires_auth
def get_domains(ctx, as_json):
    "List all registered domains and their NS info"
    try:
        r = api_call(httpx.get, f"{API_URL}/api/dns/get-domains", headers=make_headers(ctx))
        data = r.json()

        if as_json:
            print_output(r, as_json)
            return

        for entry in data.get("domains", []):
            if "error" in entry:
                click.echo(f"[ERROR] {entry['domain']}: {entry['error']}")
                continue

            click.echo(f"Domain:         {entry['domain']}")
            click.echo(f"Primary NS:     {entry.get('primary_ns', '-')}")
            click.echo(f"NS Names:       {', '.join(entry.get('nameservers', []))}")
            click.echo(f"NS IPs:         {', '.join(entry.get('ips', []))}")
            click.echo(f"Updated At:     {entry.get('updated_at', '-')}")
            click.echo(f"DNSSEC:         {entry.get('dnssec_status', 'disabled')}")
            click.echo(f"DNSSEC Action:  {entry.get('dnssec_action') or '-'}")
            click.echo(f"DNSSEC Updated: {entry.get('dnssec_updated_at') or '-'}")
            click.echo("-" * 40)

    except Exception as e:
        click.echo(f"[ERROR] Failed to fetch domain list: {e}")

@cli.command("domain-status")
@json_option()
@click.option('--domain', '-d', required=True, help="Domain to inspect")
@requires_auth
def domain_status(ctx, as_json, domain):
    """Show consolidated operational status for a domain"""
    try:
        normalized_domain = domain.strip().lower()
        r = api_call(
            httpx.get,
            f"{API_URL}/api/dns/domain-status",
            headers=make_headers(ctx),
            params={"domain": normalized_domain},
            timeout=40.0
        )
        data = r.json()

        if as_json:
            click.echo(json.dumps(data, indent=2, default=str))
            return

        click.echo(f"Domain:            {data['domain']}")
        click.echo(f"Primary NS:        {data['config'].get('primary_ns', '-')}")
        click.echo(f"NS Names:          {', '.join(data['config'].get('nameservers', []))}")
        click.echo(f"NS IPs:            {', '.join(data['config'].get('ips', []))}")
        click.echo(f"Config Updated:    {data['summary'].get('config_updated_at')}")
        click.echo(f"Record Count:      {data['summary'].get('record_count')}")
        click.echo(f"TLS Enabled:       {data['config'].get('tls_enabled')}")
        click.echo("")

        ns = data.get("nameserver_status", {})
        click.echo("Nameserver Health")
        click.echo("-----------------")
        click.echo(f"Overall:           {'Healthy' if ns.get('is_active') else 'Issue Detected'}")
        click.echo(f"Details:           {ns.get('status_details', '-')}")
        for entry in ns.get("results", []):
            click.echo(f"  - {entry.get('ip')}: {entry.get('status')}")

        prop = data.get("propagation", {})
        click.echo("")
        click.echo("NS Propagation")
        click.echo("--------------")
        click.echo(f"Status:            {prop.get('status', '-')}")
        click.echo(f"Match:             {prop.get('match')}")
        click.echo(f"Depth:             {prop.get('depth')}")
        click.echo(f"Explanation:       {prop.get('explanation', '-')}")
        if prop.get("resolved_ns"):
            click.echo(f"Resolved NS:       {', '.join(prop['resolved_ns'])}")

        dnssec = data.get("dnssec", {})
        click.echo("")
        click.echo("DNSSEC")
        click.echo("------")
        click.echo(f"Status:            {dnssec.get('status', '-')}")
        click.echo(f"Message:           {dnssec.get('message', '-')}")
        click.echo(f"Auto Resign:       {dnssec.get('auto_resign_enabled')}")
        click.echo(f"RRSIG Expiry:      {dnssec.get('days_before_rrsig_expiration')}")
        click.echo(f"Key Age (days):    {dnssec.get('days_since_last_key_creation')}")
        if dnssec.get("note"):
            click.echo(f"Note:              {dnssec.get('note')}")

        recent = data.get("recent_activity", {})
        last_dns = recent.get("last_dns_log")
        last_dnssec = recent.get("last_dnssec_log")

        click.echo("")
        click.echo("Recent Activity")
        click.echo("---------------")
        if last_dns:
            click.echo(
                f"Last DNS Change:   {last_dns.get('created_at')} | "
                f"{last_dns.get('action')} {last_dns.get('record_type')} "
                f"{last_dns.get('record_name')} -> {last_dns.get('record_value')}"
            )
        else:
            click.echo("Last DNS Change:   -")

        if last_dnssec:
            click.echo(
                f"Last DNSSEC Event: {last_dnssec.get('created_at')} | "
                f"{last_dnssec.get('action')} key_tag={last_dnssec.get('key_tag', '-')}"
            )
        else:
            click.echo("Last DNSSEC Event: -")

    except Exception as e:
        click.echo(f"[ERROR] Failed to fetch domain status: {e}")
        raise click.Abort()
    
@cli.command("deregister")
@click.option('--domain', '-d', required=True, help="Domain to deregister")
@requires_auth
def deregister(ctx, domain):
    """
    Deregister a domain from the app backend and delete zone files from nameservers.
    """
    try:
        normalized_domain = domain.strip().lower()
        confirm = click.confirm(
            f"[WARNING] This will remove '{normalized_domain}' from the backend and delete its zone from all nameservers.\nAre you sure?",
            default=False
        )
        if not confirm:
            click.echo("Aborted.")
            return

        r = api_call(
            httpx.post,
            f"{API_URL}/api/dns/deregister-domain",
            json={"domain": normalized_domain},
            headers=make_headers(ctx)
        )
        result = r.json()
        status = result.get("status")

        if status == "deregistered":
            click.echo(f"[SUCCESS] Domain '{normalized_domain}' has been deregistered and zone files deleted.")
        elif status == "not-found":
            click.echo(f"[INFO] Domain '{normalized_domain}' was not registered.")
        else:
            click.echo(f"[WARNING] Unexpected response: {result}")
    except Exception as e:
        click.echo(f"[ERROR] Failed to deregister: {e}")

@cli.command("policy-status")
@json_option()
@click.option('--domain', '-d', required=True, help="Domain to evaluate against canonical vs live DNS")
@click.option('--dkim-selector', default=None, help="Optional DKIM selector to evaluate (e.g. selector1)")
@requires_auth
def policy_status(ctx, as_json, domain, dkim_selector):
    """Show deterministic DNS/email policy evaluation for a domain"""
    try:
        normalized_domain = domain.strip().lower()
        normalized_selector = dkim_selector.strip().lower() if dkim_selector else None

        params = {}
        if normalized_selector:
            params["dkim_selector"] = normalized_selector

        r = api_call(
            httpx.get,
            f"{API_URL}/api/ai-explain/policy-eval/{normalized_domain}",
            headers=make_headers(ctx),
            params=params,
            timeout=40.0
        )
        data = r.json()

        if as_json:
            click.echo(json.dumps(data, indent=2))
            return

        click.echo(f"Domain:            {data['domain']}")
        click.echo(f"Policy Status:     {data['status']}")
        click.echo(f"DKIM Selector:     {data.get('dkim_selector') or '-'}")
        click.echo(f"Canonical Hash:    {data.get('canonical_state_hash', '-')}")
        click.echo(f"Live Hash:         {data.get('live_state_hash', '-')}")
        click.echo("")

        issues = data.get("classified_delta", [])
        if not issues:
            click.echo("Issues")
            click.echo("------")
            click.echo("No policy issues detected.")
        else:
            click.echo("Issues")
            click.echo("------")
            for issue in issues:
                click.echo(
                    f"- [{issue.get('severity', '?').upper()}] "
                    f"{issue.get('code', '-')}: {issue.get('message', '-')}"
                )

    except Exception as e:
        click.echo(f"[ERROR] Failed to fetch policy status: {e}")
        raise click.Abort()
    
@cli.command("explain-policy")
@json_option()
@click.option('--domain', '-d', required=True, help="Domain to explain")
@click.option('--audience', default="sme_owner", show_default=True, type=click.Choice(["sme_owner", "technical_operator"]))
@click.option('--tone', default="plain", show_default=True, type=click.Choice(["plain", "concise", "advisory"]))
@click.option('--dkim-selector', default=None, help="Optional DKIM selector to evaluate (e.g. selector1)")
@click.option('--use-mock', is_flag=True, default=False, help="Use mock AI response instead of real API call")
@requires_auth
def explain_policy(ctx, as_json, domain, audience, tone, dkim_selector, use_mock):
    """Explain deterministic policy findings in plain language"""
    try:
        normalized_domain = domain.strip().lower()
        normalized_selector = dkim_selector.strip().lower() if dkim_selector else None

        # Step 1: get deterministic policy result
        params = {}
        if normalized_selector:
            params["dkim_selector"] = normalized_selector

        r = api_call(
            httpx.get,
            f"{API_URL}/api/ai-explain/policy-eval/{normalized_domain}",
            headers=make_headers(ctx),
            params=params,
            timeout=40.0
        )
        policy_data = r.json()

        # Step 2: enrich for explanation route
        payload = dict(policy_data)
        payload["audience"] = audience
        payload["tone"] = tone
        payload["use_mock"] = use_mock

        # Step 3: ask AI explainer
        explain_resp = api_call(
            httpx.post,
            f"{API_URL}/api/ai-explain/from-policy-eval",
            headers=make_headers(ctx),
            json=payload,
            timeout=60.0
        )
        data = explain_resp.json()

        if as_json:
            click.echo(json.dumps(data, indent=2))
            return

        click.echo(f"Domain:            {data['domain']}")
        click.echo(f"Status:            {data['status']}")
        click.echo(f"DKIM Selector:     {policy_data.get('dkim_selector') or '-'}")
        click.echo(f"Provider:          {data.get('provider', '-')}")
        click.echo(f"Model:             {data.get('model', '-')}")
        click.echo("")
        click.echo("Summary")
        click.echo("-------")
        click.echo(data.get("summary", ""))
        click.echo("")
        click.echo("Explanation")
        click.echo("-----------")
        click.echo(data.get("explanation", ""))

        actions = data.get("recommended_actions", [])
        if actions:
            click.echo("")
            click.echo("Recommended Actions")
            click.echo("-------------------")
            for action in actions:
                click.echo(f"- {action}")

    except Exception as e:
        click.echo(f"[ERROR] Failed to explain policy: {e}")
        raise click.Abort()
    
@cli.command('devserver')
def devserver():
    """Run the app backend with hot reload (for local development)."""
    import subprocess
    subprocess.run(["uvicorn", "main:app", "--reload"])

@cli.command('env')
@click.option("--bashrc", is_flag=True, help="Append to ~/.bashrc")
@click.option("--zshrc", is_flag=True, help="Append to ~/.zshrc")
@click.option("--envfile", type=click.Path(), help="Write to a file (e.g., .env)")
def env(bashrc, zshrc, envfile):
    """
    Output or persist the environment variables needed by dnp CLI.
    """
    import getpass
    from pathlib import Path
    import os

    writing = bashrc or zshrc or envfile

    api_url = os.getenv("DNSPROOF_API_URL", "http://localhost:8000")

    #print(f"[DEBUG] Initial password from env: {password}")
    # Prompt ONLY when writing and password is missing
    password = os.getenv("DNSPROOF_PASSWORD")
    if writing and not password:
        # Prompt for API URL regardless
        default_api = "http://localhost:8000"
        api_url = click.prompt(
            "Enter DNSProof API URL (default: http://localhost:8000)", 
            default=default_api,
            show_default=False
        )

        password = getpass.getpass("Enter DNSProof password to store: ")
        print(f"[DEBUG] Password after prompt (if any): {password}")


    export_lines = [
        f'export DNSPROOF_API_URL="{api_url}"',
        f'export DNSPROOF_PASSWORD="{password}"'
    ]

    dotenv_lines = [
        f'DNSPROOF_API_URL={api_url}',
        f'DNSPROOF_PASSWORD={password}'
    ]

    if bashrc:
        path = Path.home() / ".bashrc"
        with open(path, "a") as f:
            f.write("\n# Added by dnp\n")
            f.write("\n".join(export_lines) + "\n")
        print(f"[INFO] Appended to {path}")
        print("[WARNING] This file contains your DNSProof password in plaintext.")
        print("         Do not commit to version control or share with others.")
        print("         Consider using a secure secret manager for production.")
        print(f"[INFO] Run the following command to apply:")
        print(f" source {path}")

    elif zshrc:
        path = Path.home() / ".zshrc"
        with open(path, "a") as f:
            f.write("\n# Added by dnp\n")
            f.write("\n".join(export_lines) + "\n")
        print(f"[INFO] Appended to {path}")
        print("[WARNING] This file contains your DNSProof password in plaintext.")
        print("         Do not commit to version control or share with others.")
        print("         Consider using a secure secret manager for production.")
        print(f"[INFO] Run the following command to apply:")
        print(f" source {path}")

    elif envfile:
        path = Path(envfile)
        with open(path, "w") as f:
            f.write("\n".join(dotenv_lines) + "\n")
        print(f"[INFO] Written to {path}")
        print("[WARNING] This file contains your DNSProof password in plaintext.")
        print("         Do not commit to version control or share with others.")
        print("         Consider using a secure secret manager for production.")
        print(f"[INFO] Run the following command to apply:")
        print(f" source {path}")

    else:
        raise click.UsageError(
            "No output target specified.\n\n"
            "Use one of:\n"
            "  dnp env --bashrc\n"
            "  dnp env --zshrc\n"
            "  dnp env --envfile .env"
        )


if __name__ == '__main__':
    cli()
