sudo /bin/bash -c '/srv/dns/venv/bin/python /srv/dns/dnssec_resign_cron.py >> /var/log/dnssec_resign.log 2>&1'

#--------------------------------------------------------------
# git
# to save it to dnsproof-dev
git push backup
git push backup <branch name>

# to understand the remote server
git remote -v

#--------------------------------------------------------------
# CLI
🛠 To use:

Save the script as dnp.py or package as CLI via setuptools/poetry

Run like:

export DNSPROOF_API_URL=http://localhost:8000
export DNSPROOF_PASSWORD=shiro123

python dnp.py add --domain dnsproof.org --type TXT --name hello --value world
python dnp.py logs

python dnp.py edit --domain dnsproof.org --type TXT --old-name @ --old-value test0 --new-name @ --new-value test1

python dnp.py delete --domain dnsproof.org --type TXT --name mytest --value world

python dnp.py dnssec-auto-resign on
python dnp.py dnssec-auto-resign off

# --json/ -j output examples
dnp -j dnssec-status --domain dnsproof.org
dnp dnssec-status --domain dnsproof.org --json
dnp dnssec-status --domain dnsproof.org -j

# dump json file
python dnp.py dump-zone --domain dnsproof.org --output C:/Users/shiro/Downloads/dnsproof.json

#--------------------------------------------------------------
# CLI global setup
✅ Steps to Install dnp Globally (dev mode or prod mode)
✅ Option A: Install as an editable dev package

This is best for active development.

Add pyproject.toml (if not already present)

Define the CLI entry point:

# pyproject.toml starts here
[project]
name = "dnsproof"
version = "0.1.0"
description = "DNSProof CLI"
dependencies = ["click", "httpx"]
requires-python = ">=3.8"

[project.scripts]
dnp = "cli.dnp:cli"

[tool.setuptools.packages.find]
where = ["."]
include = ["cli"]

[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.build_meta"
# pyproject.toml ends here

From the root of your repo (where pyproject.toml is):

# if you need to reinstall, first uninstall
#pip uninstall dnsproof -y
pip install -e .


✅ Now you can run dnp ... from anywhere in that Python environment.