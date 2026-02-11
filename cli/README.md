# DNSProof CLI (`dnp`)

The `dnp` CLI is the command-line interface for interacting with your DNSProof deployment. It allows you to manage DNS records, push signed zone changes, enable DNSSEC, and inspect logs — all from the terminal.

This tool is ideal for headless environments, GitOps workflows, or privacy-conscious operators who want full control over their nameserver stack.

---

## Quickstart

Before using the CLI, set these environment variables in your shell:

```bash
DNSPROOF_API_URL=http://localhost:8000
DNSPROOF_PASSWORD=your_password
```
Or run:
```bash
dnp env --bashrc
```
### 1. Initialize a domain
This registers the domain and creates a starter zone file:
```bash
dnp init --config dns_config.yaml
```
The generated zone JSON (e.g. `dnsproof.org.json`) includes minimal records. Edit it to add custom DNS entries.

### 2. Push to nameservers
```bash
dnp push-zone --zone-json <your-domain>.json
```
This deploys the zone to nameservers.

### 3. Manage records
```bash
dnp add --domain dnsproof.org --type TXT --name @ --value "hello world"
```

### 4. View logs or enable DNSSEC
```bash
dnp logs-dns --domain dnsproof.org -j
dnp dnssec-enable --domain dnsproof.org -j
```
Use `--json` (or `-j`) to print raw output with spacing.

## Installation & Setup

This section covers one-time setup: provisioning nameservers, configuring environment variables, and launching the local backend.

### Config YAML file  

Generates a DNSProof config file for your domain — including nameserver IPs, resolver type, TLS options, and more.

```bash
dnp generate-config \
  --domain dnsproof.org \
  --primary-ns ns1 \
  --ns ns1:1.2.3.4 --ns ns2:5.6.7.8 \
  --tls-enabled \
  --resolver coredns \
  --agent-cert-path-ns /srv/certs \
  --agent-cert-path-app ./certs \
  --output config.yaml
```
This produces:
```bash
domain: dnsproof.org
primary_ns: ns1
nameservers:
  ns1:
    ip: 1.2.3.4
  ns2:
    ip: 5.6.7.8
resolver: coredns
tls_enabled: true
agent_cert_path_ns: /srv/certs
agent_cert_path_app: ./certs
```
- If `--tls-enabled` is omitted, `the agent_cert_path_ns` and `agent_cert_path_app` fields are excluded.
- Paths are written exactly as passed — on Windows with Git Bash, prefer using `C:\path\to\certs` or `/c/path/to/certs` to avoid auto-rewriting by the shell.
- This config file is required for `dnp install`, `dnp init`, and most domain operations.
- Throughout this documentation, `dns_config.yaml` is used as the default path.

### Nameserver Provisioning  
Provision a nameserver VM with CoreDNS or NSD, plus the DNSProof agent and DNSSEC key generation.

```bash
dnp generate-agent-secret --copy         # Generates a new secret and copies to clipboard
dnp generate-agent-secret --show         # Prints the secret to terminal
dnp generate-agent-secret                # Saves to file, agent.secret
```
Use the generated secret when installing:
```bash
dnp install --config dns_config.yaml --agent-secret agent.secret
```
This command:
- Installs system packages (Python, firewall, DNS utils, etc.)
- Sets up the internal DNSProof agent API
- Configures resolver (`CoreDNS` or `NSD`) as defined in `dns_config.yaml`
- Enables DNSSEC signing and re-signing logic
- Auto-generates self-signed TLS certs if `tls_enabled: true` in config

`--agent-secret` is required. It authenticates API calls between your backend and the VM.
The secret can be a raw string or a path to a `.secret` file.

### Set CLI Environment Variables

The `dnp` CLI requires an API URL and password for authentication.

You can export them manually:
```bash
export DNSPROOF_API_URL="http://localhost:8000"
export DNSPROOF_PASSWORD="your_password"
```
Or use the CLI helper to persist them automatically:
```bash
dnp env --bashrc         # Append to ~/.bashrc
dnp env --zshrc          # Append to ~/.zshrc
dnp env --envfile .env   # Write to .env file
```
After writing, run `source <file>` to load them into your current shell session.  

### Launch the Development Server

Run the FastAPI backend locally — useful for testing or development.
```bash
dnp devserver
```
**!! Must be run from the `dnsproof/app/` directory.**

### Init

Initialize domain management by registering the domain and its base configuration with the backend.
```bash
dnp init --config dns_config.yaml
```
This command:
- Registers the domain in the backend database
- Stores the full `dns_config.yaml` as the authoritative configuration
- Writes an initial canonical zone JSON file locally  
(use `--output` to specify a custom path)  

This step is required before any DNS records or configuration updates can be applied.

### Set-config
Update the stored configuration for an already registered domain.
```bash
dnp set-config --file dns_config.yaml
```
This command:
- Updates the domain’s configuration in the backend database
- Does **not** push changes to nameservers
- Does **not** implicitly re‑register domains (prevents accidental typos)

### Get-config
Retrieve the configuration currently stored in the backend database.
```bash
dnp get-config --domain dnsproof.org
```
By default:
- Prints the stored configuration to stdout  

Optional:
- Use --output <path> to save it to a file  

This is useful for auditing, backups, or syncing local files with the backend source of truth.

### Get-domains  
List all registered domains along with their configuration summary.
```bash
dnp get-domains
```
This command shows:
- Domain name
- Primary nameserver (e.g. `ns1.dnsproof.org`)
- All configured NS names (FQDNs)
- Their corresponding IP addresses

Use this to audit your managed domains and confirm config consistency across the system.

## Zone File Operations  

These commands let you work directly with full zone files in JSON format — either pushing them to nameservers or fetching the current version from the backend.  

Use them for recovery, migration, manual overrides, or version-controlled zone management.  

### Push Zone  
Push a complete JSON zone file (e.g. dnsproof.org.json) directly to the nameservers.  

This command bypasses per-record signing and audit logs — it’s useful for first-time deployment or full-zone overrides.
```bash
dnp push-zone --zone-json dnsproof.org.json
```
- Validates that both domain and records are present in the JSON
- Logs all records as `push-add` or `push-delete`, with cryptographic signing
- Triggers DNS deployment and DNSSEC signing via the agent API

Use this for bootstrapping, migrations, or restoring from backup.
For incremental edits, use `add`, `edit`, or `delete`.

### Dump Zone
Download the current zone JSON from the backend.
```bash
dnp dump-zone --domain dnsproof.org --output dnsproof.org.json
```
- Returns the canonical JSON used by the backend
- Can be redirected to a file or piped for inspection
- Useful for syncing local state, versioning, or debugging


## Record Management  

Manage individual DNS records with real-time deployment and signed audit trails.  
All changes are cryptographically logged for verifiable history and reproducibility.

### View DNS Records  
Fetch active DNS records for a domain.
```bash
dnp records --domain dnsproof.org --type MX
```
- `--type` is optional (A, AAAA, MX, TXT, etc.)
- Output shows currently deployed zone state

### Add  
Add a DNS record.  
The new record is deployed immediately and logged with a signed snapshot.
```bash
dnp add --domain dnsproof.org --type A --name www --value 1.2.3.4
```

### Edit  
Edit an existing record.  
Signed before/after snapshots ensure full traceability.
```bash
dnp edit --domain dnsproof.org \
         --type A \
         --old-name www \
         --old-value 1.2.3.4 \
         --new-name www \
         --new-value 5.6.7.8
```

### Delete  
Delete a DNS record.  
The record is preserved in signed logs before removal.
```bash
dnp delete --domain dnsproof.org --type TXT --name @ --value "hello world"
```


## DNSSEC Management

Control DNSSEC lifecycle: enable signing, manage key rotation, and configure auto-resign behavior.  
All actions are cryptographically logged for full-chain auditability.

### dnssec-enable  
Enables DNSSEC for the domain.
```bash
dnp dnssec-enable --domain dnsproof.org
```
- Generates KSK/ZSK key pair
- Signs the zone and deploys DNSSEC records
- Logs key generation and signing event

### dnssec-status  
View current DNSSEC state for a domain.
```bash
dnp dnssec-status --domain dnsproof.org
```
- Shows whether DNSSEC is enabled
- Displays current DS record and earliest RRSIG expiry
- Useful for monitoring signature health

### dnssec-rotate  
Rotate both the **Key Signing Key (KSK)** and **Zone Signing Key (ZSK)**.
```bash
dnp dnssec-rotate --domain dnsproof.org
```
- Signs new keys and updates DS record
- Triggers full re-signing of the zone
- Logged for audit purposes

### dnssec-rotate-zsk  
Rotate only the **ZSK** (Zone Signing Key).
```bash
dnp dnssec-rotate-zsk --domain dnsproof.org
```
- Keeps DS record unchanged (KSK remains intact)
- Useful for routine key hygiene
- Logged with new RRSIG timestamps

### dnssec-resign  
Force a manual re-signing of the zone.
```bash
dnp dnssec-resign --domain dnsproof.org
```
- Re-generates all RRSIG record
- Uses existing keys
- Useful after TTL changes or recovery

### dnssec-auto-resign  
Enable or disable automatic re-signing before RRSIG expiry.
```bash
dnp dnssec-auto-resign --domain dnsproof.org --state off
```
- System re-signs zones ~14 days before expiration
- State is stored on agent VM
- Safe default: enabled

### dnssec-disable  
Disable DNSSEC for the domain.
```bash
dnp dnssec-disable --domain dnsproof.org
```
- Removes the DNSSEC keys from nameservers
- Signs the zone without DNSSEC keys
- Logs key deletion

## Nameserver Operations

Inspect and verify nameserver behavior across four layers:  
- **Configured**: what you defined in dns_config.yaml
- **Agent Status**:  Whether your authoritative nameserver (CoreDNS/NSD) is running as expected (active/inactive/timeout)
- **Live response**: what your nameservers are actually serving
- **Delegation**: what the global DNS hierarchy believes

### nameserver  
Show the nameservers you’ve configured in `dns_config.yaml`.
```bash
dnp nameserver --domain dnsproof.org
```
- Reflects your intended setup (e.g. `ns1.dnsproof.org`, `ns2.dnsproof.org`)
- Used internally for provisioning and zone deployment

### ns-status
Check authoritative nameserver health (CoreDNS/NSD) across all agent VMs for a domain.
```bash
dnp ns-status --domain dnsproof.org
```
This command:
- Sends a status check to each agent
- Verifies whether the local nameserver (CoreDNS or NSD) is currently running
- Returns the overall status along with per-IP results

Use this to:
- Debug downtime or unexpected zone propagation delays
- Monitor resolver process uptime across your nameserver cluster
- Validate agent responsiveness before a deployment

**Output (human-readable):**  
```bash
Domain: dnsproof.org
Overall Status: Healthy
Details: 2/ 2
----------------------------------------
1.2.3.4 - active
5.6.7.8 - active
```
If one or more agents are unresponsive:
```bash
Domain: dnsproof.org
Overall Status: Issue Detected
Details: 1/ 2
----------------------------------------
1.2.3.4 - active
5.6.7.8 - timeout
Error: Agent VM unreachable
```

**Optional:**  
Use --json or -j to output structured data:
```bash
dnp ns-status -d dnsproof.org -j
```

### verify-ns  
Query your configured nameservers directly and verify their zone content.
```bash
dnp verify-ns --domain dnsproof.org
```
- Bypasses public resolvers
- Confirms the zone is correctly served by your NS
- Useful during development or after `push-zone`

### ns-propagation  
Trace nameserver delegation through the DNS hierarchy.
```bash
dnp ns-propagation --domain dnsproof.org
```
- Follows root → TLD → your NS records recursively
- Detects mismatches between intended and delegated NS
- Returns detailed status and failure explanations

### Reference: Nameserver Verification Layers

| Command              | Layer                 | Source                     | Purpose                              |
|----------------------|-----------------------|----------------------------|---------------------------------------|
| `dnp nameserver`     | Configuration          | `dns_config.yaml`          | What you *intend* to serve            |
| `dnp verify-ns`      | Direct query           | Your actual nameservers    | What your NS *is currently serving*   |
| `dnp ns-propagation` | Delegation trace       | DNS hierarchy (root → TLD) | What the *world sees* via delegation  |

## Logs  

View and verify cryptographically signed logs across three layers:
- DNS changes (record-level modifications)
- DNSSEC configuration (enable/rotate/resign)
- Signing key lifecycle (attestation key generation)

### logs-dns    
Shows record-level changes: `add`, `edit`, `delete`, `push-add`, `push-delete`.
```bash
dnp logs-dns --limit 5
```
- Includes full before/after state
- Each log entry is signed and timestamped
- Use `--json` or `-j` for raw structured output

### logs-dnssec  
Shows DNSSEC state transitions:
```bash
dnp logs-dnssec --limit 5
```
- Includes `enable`, `disable`, `rotate`, `rotate-zsk`.
- Does **not** include routine auto-resigning events
- Useful for compliance review and root DS update tracking

### logs-signing  
Shows generation of DNSProof signing keypairs used for log attestation.

```bash
dnp logs-signing --limit 5
```
- Each key has a version, hash, and timestamp
- Changing signing keys does not affect DNSSEC
- Audit-only — no zone-level impact

### verify-log    
Verify a single log entry by its ID.
```bash
dnp verify-log --id <log-id>
```
- Validates the cryptographic signature
- Confirms log integrity without trusting backend

### verify-log-offline    
Verify logs from a local file (e.g. for air-gapped audits or export checks).
```bash
dnp verify-log-offline --file logs.json
```
- Input file must be a JSON array of log entries
- Works fully offline with embedded public keys

## Utility

Advanced tools for scripting, automation, and local development.

### record-id  
Compute the internal record ID used by DNSProof.
```bash
dnp record-id --type TXT --name @ --value "test"
```
- Deterministically hashes type + name + value
- Useful for `edit` or `delete` commands when record metadata is partial or pre-known
- Ensures consistency across CLI and backend logic

### hostsync  
Update your local `/etc/hosts` or Windows hosts file with agent IP mappings.
```bash
dnp hostsync --platform windows
```
For Linux or Mac:
```bash
dnp hostsync --platform unix
```
This is required when:
- `tls_enabled: true` is set in dns_config.yaml
- You’re running the backend or agent locally
- You use HTTPS between backend ↔ agent VM
When TLS is enabled, these hostnames must resolve:
```bash
<ns1 IP>  agent.<your-ns1>.<your-domain>
<ns2 IP>  agent.<your-ns2>.<your-domain>
```
`dnp hostsync` automates this mapping to avoid manual edits.


## Pro Tips
Add these flags to streamline usage or automate scripts:
- Use --json or -j to output structured JSON instead of human-readable logs:
```bash
dnp logs --json
```
- Use -d as a shortcut for --domain:
```bash
dnp verify-ns -d dnsproof.org
```


## Related Files
- `dns_config.yaml` — DNSProof backend configuration file
- `dnsproof.org.json` — Sample zone file (editable locally or on the agent VM)
These files are created or used by commands like `init`, `push-zone`, and `install`.

## Status
The `dnp` CLI is production-ready and used by DNSProof to manage all zone deployments.
- Deterministic record hashing
- Signed change logging
- Full reproducibility and auditability

## License
MIT — see [LICENSE](../LICENSE)