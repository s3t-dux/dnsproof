# DNSProof — Reproducibility & Dev Environment

This environment reproduces the CLI and backend setup (excluding production secrets and live DNS agents), offering verifiable consistency for development and testing.  

This folder provides reproducible infrastructure for DNSProof development using:
- Docker Compose
- Makefile shortcuts (Docker only)
- Nix Flake

## Docker
This setup runs the full DNSProof stack using Docker Compose for testing, development, and reproducibility purposes. It includes the FastAPI backend and a placeholder agent container.

### Requirements

- Docker + Docker Compose
- `.env` file in project root (see below)

### Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/yourname/dnsproof
cd dnsproof

# 2. Create .env file
cp .env.example .env
# Then edit .env to set your secrets

# 3. Start containers
docker-compose up --build
```

The app backend will be available at:  
`http://localhost:8000`

### Verify it's working
```bash
curl http://localhost:8000/
dnp init --config dns_config.yaml
dnp records -d yourdomain.com
```

### Environment Variables

The .env file supports:
```bash
AGENT_SECRET=changeme
DNSPROOF_PASSWORD=changeme
DB_PATH=/app/dnsproof.db
```

### Makefile Support

This repo includes a Makefile for easier Docker management:

```bash
make            # same as: docker-compose up --build
make docker-stop
make docker-clean
make shell      # open shell inside app container
```
These shortcuts work only for Docker Compose usage. They are not required for Nix or direct Python usage.

### About the Agent Container

This Docker Compose setup includes a placeholder dnsproof-agent container for testing.
In production, this component runs as a daemon on your nameserver VM — not in Docker.  

You can ignore this container unless you are testing full key signing or want to simulate agent API behavior.

## Nix Flake

This project provides a fully reproducible shell using `nix develop`.
It installs Python 3.13 and required system libraries. Python packages are managed separately via `pip`.

### Getting Started  
1. Enter the dev shell (requires Nix ≥ 2.4):
```bash
nix develop
```
2. Set up a virtual environment:
```bash
python -m venv venv
source venv/bin/activate
```
3. Install Python dependencies:
```bash
pip install -r app/requirements.txt
```
4. Install the `dnp` CLI:
```bash
pip install .
```
5. Start the backend server:
```bash
cd app
uvicorn main:app --reload
```

Notes
- The dev shell ensures you're always using **Python 3.13** with consistent system libraries (`sqlite`, `openssl`, etc.).
- This setup works on **Linux**, **macOS**, and **WSL2**.
- For Python 3.14 or future upgrades, edit `flake.nix` and change:
```bash
python = pkgs.python313;
```
 to e.g. `python314`, if supported.