# DNSProof CLI (`dnp`)

The `dnp` CLI is the command-line interface for interacting with your DNSProof deployment. It allows you to manage DNS records, push signed zone changes, enable DNSSEC, and inspect logs — all from the terminal.

This tool is ideal for headless environments, GitOps workflows, or privacy-conscious operators who want full control over their nameserver stack.

---

## Quickstart

Make sure your `.env` contains:

<pre><code>```bash
DNSPROOF_API_URL=http://localhost:8000
DNSPROOF_PASSWORD=your_password
```</code></pre>

Then run, for example
```bash
dnp add --domain dnsproof.org --type TXT --name @ --value "hello world"
dnp logs --domain dnsproof.org
dnp dnssec-enable --domain dnsproof.org
```

## Record Management
- **Add**  
<pre><code>```bash
dnp add --domain dnsproof.org --type A --name www --value 1.2.3.4
```</code></pre>

- **Edit**  
<pre><code>```bash
dnp edit --domain dnsproof.org \
         --type A \
         --old-name www \
         --old-value 1.2.3.4 \
         --new-name www \
         --new-value 5.6.7.8
```</code></pre>

- **Delete** 
<pre><code>```bash
dnp delete --domain dnsproof.org --type TXT --name @ --value "hello world"
```</code></pre>

- **List** 
<pre><code>```bash
dnp list --domain dnsproof.org
```</code></pre>

## DNSSEC Management
- **dnssec-enable** 
<pre><code>```bash
dnp dnssec-enable --domain dnsproof.org
```</code></pre>
- **dnssec-status** 
<pre><code>```bash
dnp dnssec-status --domain dnsproof.org
```</code></pre>
- **dnssec-rotate** 
<pre><code>```bash
dnp dnssec-rotate --domain dnsproof.org
```</code></pre>
- **dnssec-rotate-zsk** 
<pre><code>```bash
dnp dnssec-rotate-zsk --domain dnsproof.org
```</code></pre>
- **dnssec-resign** 
<pre><code>```bash
dnp dnssec-resign --domain dnsproof.org
```</code></pre>
- **dnssec-auto-resign** 
<pre><code>```bash
dnp dnssec-auto-resign on
```</code></pre>
- **dnssec-status** 
<pre><code>```bash
dnp dnssec-status on
```</code></pre>

## Zone + NS Operations
- **dump-zone**  
<pre><code>```bash
dnp dump-zone --domain dnsproof.org
```</code></pre>
- **push-zone**  
<pre><code>```bash
dnp push-zone --domain dnsproof.org --yes
```</code></pre>
- **verify-ns**  
<pre><code>```bash
dnp verify-ns --domain dnsproof.org
```</code></pre>
- **ns-propagation**  
<pre><code>```bash
dnp ns-propagation --domain dnsproof.org
```</code></pre>

## Logs
- **Logs**
<pre><code>```bash
dnp logs --limit 5
```</code></pre>

## Utility
- **record-id**
<pre><code>```bash
dnp record-id --type TXT --name @ --value "test"
```</code></pre>

## Auth + Environment
<pre><code>```bash
export DNSPROOF_PASSWORD="your_password"
export DNSPROOF_API_URL="http://localhost:8000"
```</code></pre>

## Related Files
- dns_config.yaml — sample configuration for the DNSProof backend
- dnsproof.org.json — sample zone file (stored locally or on agent VMs)

## Pro Tip
Use `--json` or `-j` on any command to output raw JSON instead of human-readable logs:
<pre><code>```bash
dnp logs --json
```</code></pre>

Use `-d dnsproof.org` which is short for `--domain`
<pre><code>```bash
dnp verify-ns -d dnsproof.org
```</code></pre>

## Status
The CLI is production-ready and used internally by DNSProof to manage all zone deployments. Full reproducibility and deterministic record hashing are supported.

## License
MIT — see LICENSE