# DNSProof

**DNSProof** is an open, reproducible, and self-hostable toolkit for running authoritative nameservers with cryptographically signed changelogs and DNSSEC support. It brings full auditability and developer-friendly control to a part of the internet that's long been opaque, centralized, and unverifiable.

## Key Features

- **Deterministic DNS change logs**  
  Track every DNS record update with cryptographic integrity and timestamped history.

- **DNSSEC made practical**  
  Integrated DNSSEC support with automatic zone signing and key management.

- **Minimal 2-VM architecture**  
  Lightweight and production-tested setup for running your own nameservers.

- **API + CLI-based control plane**  
  Submit, verify, and sign DNS changes programmatically — ideal for GitOps and automation.

- **Built-in audit log explorer**  
  Easily inspect historical changes through a simple web UI or command line.

- **Reproducibility manifest**  
  Docker Compose and Nix Flake support for verifiable, bit-for-bit identical deployments.

## Why DNSProof?

Most current DNS systems are either:
- **Centralized SaaS providers** (e.g., Cloudflare, Route53) that offer convenience but no visibility, or
- **Self-hosted BIND/CoreDNS setups** that are opaque, fragile, and nearly impossible to audit.

DNSProof solves this by providing:
- A semantic understanding of record changes — not just raw diffs
- Cryptographic proof of every mutation
- Full user sovereignty without third-party lock-in
- A realistic, scriptable setup that's already been battle-tested in production via the [StackDNS.io](https://stackdns.io) platform

## Project Status

DNSProof is currently being extracted and generalized from StackDNS's live infrastructure. Development is ongoing, and the first public release will include:

- Provisioning scripts for CoreDNS or NSD-based VMs  
- A signing and logging backend built in FastAPI  
- A minimal but usable frontend dashboard  
- CLI tools for DNS management and log verification

## Preview Resources

While the full codebase is still being prepared for public release, the following files are now available in this repository:

- `docs/cli.md` — Full documentation for the `dnp` CLI
- `examples/dns_config.yaml` — Sample configuration file
- `examples/dnsproof.org.json` — Example zone file format
- `examples/demo_logs.json` — Realistic signed DNS change logs

These illustrate the reproducibility, auditability, and developer experience behind DNSProof’s approach.

A short video demo is also available at: [https://stackdns.io/nlnetdemo](https://stackdns.io/nlnetdemo)

Want early access to the backend code? [Open an issue](https://github.com/s3t-dux/dnsproof/issues) or reach out via the contact form at [stackdns.io](https://stackdns.io).
