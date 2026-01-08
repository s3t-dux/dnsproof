#!/bin/bash

# Run: "bash push-dnsagent.sh dns-vm"

VMNAME=$1
PROJECT=nameserver-platform
ZONE=us-central1-a  # or your actual zone

echo "[SYNC] Uploading dnsproof/*.py files to $VMNAME..."

gcloud compute scp dnsproof/* "$VMNAME:/tmp/" \
  --project="$PROJECT" \
  --zone="$ZONE"

echo "[SYNC] Moving files and restarting agent..."

gcloud compute ssh "$VMNAME" \
  --project="$PROJECT" \
  --zone="$ZONE" \
  --command "sudo mkdir -p /srv/dns/ && sudo mv /tmp/*.py /srv/dns/ && sudo chown root:root /srv/dns/*.py && sudo systemctl restart dnsagent"

echo "[DONE] DNSAgent updated and restarted on $VMNAME."

