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

@cli.command('records')
@json_option()
@click.option('--domain', '-d', required=True, help="Domain name to query")
@click.option('--type', 'rtype', default=None, help="Filter by record type (e.g. A, TXT, MX)")
@requires_auth
def records(ctx, as_json, domain, rtype):
    """Get current DNS records from zone file"""
    try:
        url = f"{API_URL}/api/dns/records?domain={domain}"
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
            "domain": domain,
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

        # Backend resolves identity
        if record_id:
            payload = {
                "domain": domain,
                "record_ids": [record_id]
            }
        else:
            payload = {
                "domain": domain,
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
        r = api_call(httpx.request, 
                    "GET", 
                    f"{API_URL}/api/dns/dump/",
                    headers=make_headers(ctx),
                    params={"domain": domain}
        )
        zone_json = r.json()["zone_json"]
        if output:
            with open(output, "w") as f:
                json.dump(zone_json, f, indent=2)
            click.echo(f"Zone JSON for '{domain}' written to {output}")
        else:
            click.echo(json.dumps(zone_json, indent=2))

    except Exception as e:
        click.echo(f"Error: {e}")

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

@cli.command('dnssec-status')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_status(ctx, as_json, domain):
    "Check DNSSEC status for a domain"
    r = api_call(httpx.get, f"{API_URL}/api/dnssec/status/{domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-enable')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_enable(ctx, as_json, domain):
    "Enable DNSSEC for a domain"
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/enable/{domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-disable')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_disable(ctx, as_json, domain):
    "Disable DNSSEC for a domain"
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/disable/{domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-rotate')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_rotate(ctx, as_json, domain):
    "Rotate DNSSEC keys for a domain"
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/rotate/{domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-rotate-zsk')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_rotate_zsk(ctx, as_json, domain):
    "Rotate DNSSEC ZSK for a domain"
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/rotate/zsk/{domain}", headers=make_headers(ctx))
    print_output(r, as_json)


@cli.command('dnssec-resign')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def dnssec_resign(ctx, as_json, domain):
    "Re-sign the DNS zone for a domain"
    r = api_call(httpx.post, f"{API_URL}/api/dnssec/resign/{domain}", headers=make_headers(ctx))
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
        url += f"&domain={domain}"

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
        url += f"&domain={domain}"

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

@cli.command('verify-ns')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def verify_ns(ctx, as_json, domain):
    "Query each agent directly for NS records"
    r = api_call(httpx.get, f"{API_URL}/api/ns/verify-ns/{domain}", headers=make_headers(ctx))
    print_output(r, as_json)

@cli.command('ns-propagation')
@json_option()
@click.option('--domain', '-d', required=True)
@requires_auth
def ns_propagation(ctx, as_json, domain):
    """Check if NS records are fully propagated"""
    try:
        r = api_call(httpx.get, f"{API_URL}/api/ns/ns-propagation-status/{domain}", headers=make_headers(ctx), timeout=35.0)
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
    r = api_call(httpx.get, f"{API_URL}/api/ns/nameservers/{domain}", headers=make_headers(ctx))
    print_output(r, as_json)

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
    
@cli.command('install')
@click.option('--config', '-c', required=True, type=click.Path(exists=True), help="Path to dns_config.yaml")
@click.option('--agent-secret', '-s', required=True, help="Shared HMAC secret for agent authentication")
def install_nameservers(config, agent_secret):
    """Provision a nameserver VM using ns_provision.sh"""
    try:
        script_path = Path("ns_provision.sh").resolve()
        if not script_path.exists():
            raise click.ClickException(f"Missing provisioning script at: {script_path}")

        click.echo(f"[INFO] Running nameserver provisioning script...")
        click.echo(f"  Config:        {config}")
        click.echo(f"  Agent Secret:  (hidden)")
        click.echo("-" * 60)

        process = subprocess.Popen(
            ["bash", str(script_path), "--config", str(Path(config).resolve()), "--agent-secret", agent_secret],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in iter(process.stdout.readline, ''):
            click.echo(line.strip())

        process.stdout.close()
        return_code = process.wait()

        if return_code != 0:
            click.echo(f"[ERROR] Script exited with code {return_code}")
            raise click.Abort()

        # ✅ Step 2: Move FastAPI agent files to /srv/dns
        click.echo("[INFO] Copying internal DNS agent files to /srv/dns/")
        os.makedirs("/srv/dns", exist_ok=True)
        for pyfile in Path("dnsproof").glob("*.py"):
            dest = Path("/srv/dns") / pyfile.name
            shutil.copy2(pyfile, dest)
            os.chown(dest, 0, 0)  # Set root:root ownership

        # ✅ Step 3: Restart agent service
        click.echo("[INFO] Restarting dnsagent service...")
        subprocess.run(["systemctl", "restart", "dnsagent"], check=False)

        click.echo("[SUCCESS] Nameserver provisioned and agent restarted.")

    except Exception as e:
        click.echo(f"[FATAL] Installation failed: {e}")
        raise click.Abort()

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
        r = api_call(
            httpx.post,
            f"{API_URL}/api/dns/register-domain",
            json={"domain": domain},
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

@cli.command("deregister")
@click.option('--domain', '-d', required=True, help="Domain to deregister")
@requires_auth
def deregister(ctx, domain):
    """
    Deregister a domain from the app backend and delete zone files from nameservers.
    """
    try:
        confirm = click.confirm(
            f"[WARNING] This will remove '{domain}' from the backend and delete its zone from all nameservers.\nAre you sure?",
            default=False
        )
        if not confirm:
            click.echo("Aborted.")
            return

        r = api_call(
            httpx.post,
            f"{API_URL}/api/dns/deregister-domain",
            json={"domain": domain},
            headers=make_headers(ctx)
        )
        result = r.json()
        status = result.get("status")

        if status == "deregistered":
            click.echo(f"[SUCCESS] Domain '{domain}' has been deregistered and zone files deleted.")
        elif status == "not-found":
            click.echo(f"[INFO] Domain '{domain}' was not registered.")
        else:
            click.echo(f"[WARNING] Unexpected response: {result}")
    except Exception as e:
        click.echo(f"[ERROR] Failed to deregister: {e}")

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
