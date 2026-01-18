sudo /bin/bash -c '/srv/dns/venv/bin/python /srv/dns/dnssec_resign_cron.py >> /var/log/dnssec_resign.log 2>&1'

#--------------------------------------------------------------
# CLI
🛠 To use:

Save the script as dnp.py or package as CLI via setuptools/poetry

Run like:

export DNSPROOF_API_URL=http://localhost:8000
export DNSPROOF_PASSWORD=yourpassword

python dnp.py add --domain dnsproof.org --type TXT --name hello --value world
python dnp.py logs