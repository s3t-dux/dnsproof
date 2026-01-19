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

python dnp.py edit --domain dnsproof.org --type TXT --old-name @ --old-value test2 --new-name @ --new-value test0