# DNSProof CLI (`dnp`)

The `dnp` CLI is the command-line interface for interacting with your DNSProof deployment. It allows you to manage DNS records, push signed zone changes, enable DNSSEC, and inspect logs — all from the terminal.

This tool is ideal for headless environments, GitOps workflows, or privacy-conscious operators who want full control over their nameserver stack.

---

## Quickstart

Make sure your `.env` contains:

```bash
DNSPROOF_API_URL=http://localhost:8000
DNSPROOF_PASSWORD=your_password
```

Then run, for example
```bash
dnp add --domain dnsproof.org --type TXT --name @ --value "hello world"
dnp logs --domain dnsproof.org
dnp dnssec-enable --domain dnsproof.org
```

## Record Management
- **Add**  
```bash
dnp add --domain dnsproof.org --type A --name www --value 1.2.3.4
```

- **Edit**  
```bash
dnp edit --domain dnsproof.org \
         --type A \
         --old-name www \
         --old-value 1.2.3.4 \
         --new-name www \
         --new-value 5.6.7.8
```

- **Delete** 
```bash
dnp delete --domain dnsproof.org --type TXT --name @ --value "hello world"
```

- **List** 
```bash
dnp list --domain dnsproof.org
```

## DNSSEC Management
- **dnssec-enable** 
```bash
dnp dnssec-enable --domain dnsproof.org
```
- **dnssec-status** 
```bash
dnp dnssec-status --domain dnsproof.org
```
- **dnssec-rotate** 
```bash
dnp dnssec-rotate --domain dnsproof.org
```
- **dnssec-rotate-zsk** 
```bash
dnp dnssec-rotate-zsk --domain dnsproof.org
```
- **dnssec-resign** 
```bash
dnp dnssec-resign --domain dnsproof.org
```
- **dnssec-auto-resign** 
```bash
dnp dnssec-auto-resign on
```
- **dnssec-status** 
```bash
dnp dnssec-status on
```

## Zone + NS Operations
- **dump-zone**  
```bash
dnp dump-zone --domain dnsproof.org
```
- **push-zone**  
```bash
dnp push-zone --domain dnsproof.org --yes
```
- **verify-ns**  
```bash
dnp verify-ns --domain dnsproof.org
```
- **ns-propagation**  
```bash
dnp ns-propagation --domain dnsproof.org
```

## Logs
- **Logs**
```bash
dnp logs --limit 5
```

## Utility
- **record-id**
```bash
dnp record-id --type TXT --name @ --value "test"
```

## Auth + Environment
```bash
export DNSPROOF_PASSWORD="your_password"
export DNSPROOF_API_URL="http://localhost:8000"
```

## Related Files
- dns_config.yaml — sample configuration for the DNSProof backend
- dnsproof.org.json — sample zone file (stored locally or on agent VMs)

## Pro Tip
Use `--json` or `-j` on any command to output raw JSON instead of human-readable logs:
```bash
dnp logs --json
```

Use `-d dnsproof.org` which is short for `--domain`
```bash
dnp verify-ns -d dnsproof.org
```

## Status
The CLI is production-ready and used internally by DNSProof to manage all zone deployments. Full reproducibility and deterministic record hashing are supported.

## License
MIT — see [LICENSE](../LICENSE)