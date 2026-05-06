# DNSProof CLI (`dnp`)

The `dnp` CLI is the command-line interface for interacting with your DNSProof deployment. It allows you to manage DNS records, push signed zone changes, enable DNSSEC, inspect logs, evaluate policy posture, and explain issues in plain language — all from the terminal.

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

### 5. Inspect policy posture
```bash
dnp policy-status --domain dnsproof.org
```

### 6. Explain issues in plain language
```bash
dnp explain-policy --domain dnsproof.org
```
Use `--json` (or `-j`) to print raw output with spacing.


## Conceptual Model
DNSProof separates domain management into three distinct layers:
```
config (YAML)  → infrastructure intent
zone (JSON)    → DNS state
logs           → mutation history
```

### Config (dns_config.yaml)
- Defines infrastructure intent
- Nameservers, resolver type, TLS settings, agent paths
- Stored in the backend as the authoritative configuration

This answers:
> Where and how should this domain be served?

### Zone (JSON)
- Defines the current DNS state
- Fully resolved, canonical representation of all records
- Edited locally and pushed to nameservers

This answers:
> What records should exist right now?

### Logs
- Record all mutations (add, edit, delete, push-*)
- Cryptographically signed for auditability
- Can be verified independently of the backend

This answers:
> How did the state change over time?

### Why this separation matters
- Config changes do **not** automatically affect DNS state
- Zone changes do **not** modify infrastructure
- Logs provide a verifiable history independent of both

This separation enables:
- reproducible deployments
- safe configuration updates
- auditability without trusting the control plane

## End-to-End Domain Lifecycle
DNSProof is designed around a **portable, reproducible domain lifecycle**.  
The workflow below shows the complete flow in practice.

```bash
# 1. Generate config
dnp generate-config --domain example.org --output dns_config.yaml

# 2. Initialize domain (register + create starter zone)
dnp init --config dns_config.yaml

# 3. Modify zone locally
vim example.org.json

# 4. Deploy to nameservers
dnp push-zone --zone-json example.org.json

# 5. Export portable bundle
dnp export-domain --domain example.org --output bundle/

# 6. Recover elsewhere (or rehydrate state)
dnp import-domain \
  --config bundle/dns_config.yaml \
  --zone   bundle/example.org.json
```

### What this demonstrates
- **Local-first control**
Zone state is edited locally as JSON, then pushed to nameservers.
- **Deterministic deployment**
`push-zone` applies a full canonical state with signed logs.
- **Portability**
`export-domain` produces a self-contained bundle:
  - `dns_config.yaml` (control-plane config)
  - `<domain>.json` (canonical zone)
- **Rehydration**
`import-domain` restores:
  - domain registration (if missing)
  - stored configuration
  - deployed zone state

### Lifecycle model
DNSProof follows a simple, explicit lifecycle:
```
generate-config → init → edit → push → export → import
```
This enables:
- reproducible DNS deployments
- environment-to-environment migration
- auditable and portable domain state

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

### Generate App Master Key

Generate a base64-url-safe 32-byte `APP_MASTER_KEY` for encrypting stored agent credentials.
This key is used by the app to encrypt and decrypt agent secrets used for nameserver authentication.

```bash
dnp generate-app-key
```
Example output:
```bash
APP_MASTER_KEY=your_generated_key_here
```
Add the output to your `.env` file:
```bash
dnp generate-app-key >> .env
```
Keep this key stable. If APP_MASTER_KEY changes, existing encrypted agent secrets cannot be decrypted.

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

Initialize a domain by performing both:

- **backend registration** (control-plane state)
- **local bootstrap** (initial zone file)
```bash
dnp init --config dns_config.yaml
```
This command:
- Registers the domain in the backend database
- Stores the full `dns_config.yaml` as the authoritative configuration
- Writes an initial canonical zone JSON file locally  
(use `--output` to specify a custom path)  

This step is required before any DNS records or configuration updates can be applied.


### Add Hosted Zone

Add a new authoritative zone to an existing DNSProof nameserver fleet.

This is used when the nameserver infrastructure already exists, and you want another domain to be served by those same nameservers. For example, `example.org` can be hosted on nameservers under `dnsproof.org` without provisioning a new nameserver VM.

```bash
dnp add-hosted-zone \
  --domain example.org \
  --nameserver-domain dnsproof.org
```

This command:
- Registers the new hosted zone in the backend
- Generates an initial SOA/NS zone state for the new domain
- Stores a generated `mode: hosted_zone` config for the new domain
- Reuses the existing nameserver fleet and agent credentials from `--nameserver-domain`
- Pushes the new zone to the existing nameserver agents
- Prints registrar delegation records to apply at the domain registrar

Example delegation output:
```bash
example.org NS ns1.dnsproof.org.
example.org NS ns2.dnsproof.org.
```

Use `--force` to overwrite an already registered hosted zone:
```bash
dnp add-hosted-zone \
  --domain example.org \
  --nameserver-domain dnsproof.org \
  --force
```

Optional flags:
```bash
--ttl 3600          # TTL for generated SOA/NS records
--no-txt-marker    # Skip the default DNSProof marker TXT record
--json             # Print raw structured output
```

Conceptually:
- `dnp init` initializes a self-hosted / in-bailiwick DNSProof domain
- `dnp add-hosted-zone` adds another zone to an already provisioned nameserver fleet

After adding the hosted zone, update the domain registrar to delegate the domain to the NS records printed by the command. Then verify:
```bash
dnp records -d example.org
dnp ns-status -d example.org
dnp ns-propagation -d example.org
```

### Set-agent-secret

Update the app-side encrypted agent secret for a specific nameserver.

```bash
dnp set-agent-secret --domain dnsproof.org --nameserver ns1
```

This command updates the secret stored in the backend database for app → nameserver agent authentication.

It does **not** change the secret on the nameserver VM itself.
Use it after manually updating `AGENT_SECRET` on the nameserver and restarting the DNSProof agent.

Typical workflow:
```bash
# 1. SSH into the nameserver VM
ssh user@<ns1-ip>

# 2. Update AGENT_SECRET in the agent environment/systemd config
# 3. Restart the dnsagent service

# 4. Update the app-side encrypted copy
dnp set-agent-secret --domain dnsproof.org --nameserver ns1

# 5. Verify app → agent authentication
dnp ns-status --domain dnsproof.org
```
Optional:
```bash
dnp set-agent-secret \
  --domain dnsproof.org \
  --nameserver ns1 \
  --agent-ip 1.2.3.4
```
Use `--agent-ip` when you want the backend to validate or update the stored IP for that nameserver.

Use `--force` to skip the confirmation prompt:
```bash
dnp set-agent-secret --domain dnsproof.org --nameserver ns1 --force
```

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

### Domain-status
Inspect the current operational state of a single domain.

```bash
dnp domain-status --domain dnsproof.org
```
This command consolidates domain-level status across multiple layers:
- stored config freshness
- canonical zone record count
- nameserver health
- NS propagation
- DNSSEC posture
- most recent DNS and DNSSEC activity

Use this when you want a deeper view than get-domains provides.  

It is especially useful for:
- confirming that a domain is fully deployed and healthy
- checking whether delegation has propagated
- verifying whether DNSSEC is signed and published
- reviewing the latest operational activity for a domain

Output includes:  
- Domain name
- Primary nameserver
- Configured NS names and IPs
- Last config update time
- Current record count
- Nameserver health across agent VMs
- Delegation / propagation status
- DNSSEC status and signature health
- Most recent DNS change
- Most recent DNSSEC event

Use `--json` or `-j` for structured output:
```bash
dnp domain-status --domain dnsproof.org --json
```

Conceptually:
- `get-domains` → fleet-level overview
- `domain-status` → single-domain deep view

### Policy-status

Inspect the current DNS/email policy posture of a single domain by comparing:
- canonical DNS state stored in DNSProof
- live DNS state observed from public resolvers
```bash
dnp policy-status --domain dnsproof.org
```

This command performs deterministic policy evaluation and highlights meaningful issues such as:
- missing DMARC
- weak DMARC policy (`p=none`)
- SPF absence or mismatch
- MX mismatch

Use this when you want policy-level legibility rather than raw record inspection.
Output includes:
- domain name
- overall policy status (`secure`, `warning`, `invalid`)
- canonical vs live state hashes
- structured issue list (`classified_delta`)

Use `--json` or `-j` for structured output:
```bash
dnp policy-status --domain dnsproof.org --json
```
Conceptually:
- `domain-status` → operational state
- `policy-status` → policy interpretation of canonical vs live DNS

### Explain-policy

Explain deterministic policy findings in plain language.
```bash
dnp explain-policy --domain dnsproof.org
```

This command:
- runs deterministic policy evaluation
- sends the classified result to the AI explanation layer
- returns a concise explanation of:
  - what the issue means
  - what practical risk it creates
  - what to fix next

Optional controls:
```bash
dnp explain-policy --domain dnsproof.org --audience sme_owner --tone plain
```
Supported options:
- `--audience` → `business_owner` or `technical_operator`
- `--tone` → `plain`, `concise`, or `advisory`
- `--use-mock` → use mock explanation output instead of a live AI call

Use `--json` or `-j` for structured output:
```bash
dnp explain-policy --domain dnsproof.org --json
```
Design note:
- deterministic logic remains the source of truth
- AI does not decide correctness
- AI explains already-classified policy results

Conceptually:
- `policy-status` → deterministic policy evaluation
- `explain-policy` → human-readable explanation layer

## Zone File Operations  

These commands let you work directly with full zone files in JSON format — either pushing them to nameservers or fetching the current version from the backend.  

Use them for recovery, migration, manual overrides, or version-controlled zone management.  

### Push Zone

Push a complete JSON zone file (e.g. dnsproof.org.json) directly to the nameservers.  
This command performs a **full state replacement** of the zone.
```bash
dnp push-zone --zone-json dnsproof.org.json
```
- Treats the provided JSON as the authoritative source of truth
- Computes differences and logs them as `push-add` / `push-delete`
- Triggers DNS deployment and DNSSEC signing via the agent API

Semantics in comparison:

- `add` / `edit` / `delete` → incremental, record-level mutations
- `push-zone` → full-state override

Use this for:
- initial deployment
- migrations
- restoring from exported bundles

### Dump Zone
Download the current zone JSON from the backend.
```bash
dnp dump-zone --domain dnsproof.org --output dnsproof.org.json
```
- Returns the canonical JSON used by the backend
- Can be redirected to a file or piped for inspection
- Useful for syncing local state, versioning, or debugging

### Export Domain
Export a domain as a portable bundle:
```bash
dnp export-domain --domain dnsproof.org --output exports/dnsproof.org
```
Output:
```
dns_config.yaml
<domain>.json
```
- `dns_config.yaml`: control-plane configuration
- `<domain>.json`: canonical zone state. 

This provides a reconstructible domain snapshot, enabling migration, audit, and deterministic rehydration of DNS state.  

### Import Domain. 
Restore a domain from a portable bundle:
```bash
dnp import-domain --config dns_config.yaml --zone dnsproof.org.json
```
Semantics:
- register if missing
- update config if present
- push canonical zone

This rehydrates a domain into a consistent control-plane + zone state.  

## Record Management  
These commands operate at the **incremental mutation layer**, updating the zone through signed, per-record changes.
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
dnp add --domain dnsproof.org --type TXT --name @ --value "hello world"
```
Structured records use type-specific fields.
MX:
```bash
dnp add \
  --domain dnsproof.org \
  --type MX \
  --name @ \
  --priority 10 \
  --value mail.dnsproof.org.
```
SRV:
```bash
dnp add \
  --domain dnsproof.org \
  --type SRV \
  --name _sip._tcp \
  --priority 10 \
  --weight 5 \
  --port 5060 \
  --target sip.dnsproof.org.
```
CAA:
```bash
dnp add \
  --domain dnsproof.org \
  --type CAA \
  --name @ \
  --flag 0 \
  --tag issue \
  --value letsencrypt.org
```

### Edit  
Edit an existing record.  
Signed before/after snapshots ensure full traceability.

The safest path is to use record_id from dnp records:
```bash
dnp records --domain dnsproof.org --type MX

dnp edit \
  --domain dnsproof.org \
  --record-id <record-id> \
  --new-type MX \
  --new-name @ \
  --new-priority 20 \
  --new-value mail2.dnsproof.org.
```
You can also identify the old record by its full structured identity:
```bash
dnp edit \
  --domain dnsproof.org \
  --type SRV \
  --old-name _sip._tcp \
  --old-priority 10 \
  --old-weight 5 \
  --old-port 5060 \
  --old-target sip.dnsproof.org. \
  --new-name _sip._tcp \
  --new-priority 10 \
  --new-weight 10 \
  --new-port 5060 \
  --new-target sip.dnsproof.org.
```
For CAA records:
```bash
dnp edit \
  --domain dnsproof.org \
  --type CAA \
  --old-name @ \
  --old-flag 0 \
  --old-tag issue \
  --old-value letsencrypt.org \
  --new-name @ \
  --new-flag 0 \
  --new-tag issue \
  --new-value pki.goog
``` 


### Delete  
Delete a DNS record.  
The record is preserved in signed logs before removal.

The safest path is to delete by record_id:
```bash
dnp records --domain dnsproof.org --type CAA

dnp delete \
  --domain dnsproof.org \
  --record-id <record-id>
```
You can also delete by full structured record identity.  
A:
```bash
dnp delete \
  --domain dnsproof.org \
  --type A \
  --name @ \
  --value 1.2.3.4
```
MX:
```bash
dnp delete \
  --domain dnsproof.org \
  --type MX \
  --name @ \
  --priority 10 \
  --value mail.dnsproof.org.
```
SRV:
```bash
dnp delete \
  --domain dnsproof.org \
  --type SRV \
  --name _sip._tcp \
  --priority 10 \
  --weight 5 \
  --port 5060 \
  --target sip.dnsproof.org.
```
CAA:
```bash
dnp delete \
  --domain dnsproof.org \
  --type CAA \
  --name @ \
  --flag 0 \
  --tag issue \
  --value letsencrypt.org
```
For structured records, the type-specific fields are part of the canonical record identity. If deletion or editing fails, run `dnp records --domain <domain> --type <TYPE>` and copy the exact fields or use the displayed `record_id`.


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

## Signing Key  

### Show Active Signing Key  
Displays metadata for the currently active DNS record signing key.  
This key is used to cryptographically sign all DNS change log entries (DNSChangeLog). Only one signing key should be active at any given time.
```bash
dnp signing active-key
```
The active key includes:
- ID — Internal key lifecycle identifier
- Created — Timestamp of key generation
- Type — Key category (e.g., dns_record)
- Purpose — Optional key purpose metadata
- Fingerprint — SHA-256 hash of the public key
- Public Key — Base64-encoded Ed25519 public key
- Key Path — Local filesystem path of the private key

Example:
```bash
$ dnp signing active-key

Active Signing Key
------------------
ID          : a91c21...
Created     : 2026-02-15T08:12:03
Type        : dns_record
Purpose     : None
Fingerprint : 7d8e4c...
Public Key  : Gk3...
Key Path    : /home/user/.dnsproof/signing_key
```

### List All Signing Keys  
Shows the full signing key lifecycle, including the active key and all revoked keys.
```bash
dnp signing keys
```
This command is useful for auditing key continuity.
It displays:
- The current active signing key
- All previously used keys
- Revocation timestamps (revoked_at)
- Replacement links (replaced_by)
Example:
```bash
$ dnp signing keys

Active Signing Key
------------------
ID          : a91c21...
Created     : 2026-02-15T08:12:03
Fingerprint : 7d8e4c...

Revoked Keys
------------
- ID=b73fa9..., revoked_at=2026-02-15T08:12:03, replaced_by=a91c21...
- ID=89ff12..., revoked_at=2026-02-10T04:55:28, replaced_by=b73fa9...
```
Use this to verify that:
- Exactly one key is active
- All previous keys are correctly revoked
- The signing lineage forms a continuous chain

### Rotate Signing Key  
Rotates the local DNS record signing key used for cryptographically signing DNS change logs.
```bash
dnp signing rotate
```
This command:
- Revokes the currently active signing key
- Generates a new Ed25519 signing key
- Creates a timestamped backup of the previous key on disk
- Preserves full lifecycle history in the database
- User `--force` or `-f` to skip the confirmation prompt

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