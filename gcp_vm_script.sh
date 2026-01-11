# preconfigure and deploy VM

gcloud compute addresses create dns-ip \
  --region=us-central1 

gcloud compute instances create dns-vm \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --address=dns-ip \
  --tags=dns-server,agent-vm \
  --boot-disk-size=10GB \
  --scopes=compute-rw

# 1. Test on Amazon Linux 2023 (yum)
# --image-family=amazon-linux-2023
# --image-project=amazon-cloud


VMNAME=dns-vm
PROJECT=nameserver-platform
ZONE=us-central1-a

gcloud compute scp bootstrap_vm_portable.sh $VMNAME:/tmp/bootstrap_vm_portable.sh \
  --project=$PROJECT \
  --zone=$ZONE

gcloud compute ssh $VMNAME \
  --project=$PROJECT \
  --zone=$ZONE \
  --command "sudo apt-get update && sudo apt-get install -y dos2unix && dos2unix /tmp/bootstrap_vm_portable.sh && chmod +x /tmp/bootstrap_vm_portable.sh && sudo /tmp/bootstrap_vm_portable.sh"


# 2. Test on Rocky Linux 10 (dnf)
# --image-family=rocky-linux-9
# --image-project=rocky-linux-cloud
# for Rocky Linux, the disk size has to be at least equal to the image size (20GB)
gcloud compute instances create dns-vm \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=rocky-linux-10 \
  --image-project=rocky-linux-cloud \
  --address=dns-ip \
  --tags=dns-server,agent-vm \
  --boot-disk-size=20GB \
  --scopes=compute-rw

gcloud compute scp bootstrap_vm_portable.sh $VMNAME:/tmp/bootstrap_vm_portable.sh \
  --project=$PROJECT \
  --zone=$ZONE

gcloud compute ssh $VMNAME \
  --project=$PROJECT \
  --zone=$ZONE \
  --command "sudo dnf install -y dos2unix && dos2unix /tmp/bootstrap_vm_portable.sh && chmod +x /tmp/bootstrap_vm_portable.sh && sudo /tmp/bootstrap_vm_portable.sh"

# 3. Test on Debian
gcloud compute instances create dns-vm \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=debian-13 \
  --image-project=debian-cloud \
  --address=dns-ip \
  --tags=agent-vm,dns-server \
  --boot-disk-size=10GB \
  --scopes=compute-rw

gcloud compute scp bootstrap_vm_portable.sh $VMNAME:/tmp/bootstrap_vm_portable.sh \
  --project=$PROJECT \
  --zone=$ZONE

gcloud compute ssh $VMNAME \
  --project=$PROJECT \
  --zone=$ZONE \
  --command "sudo apt-get update && sudo apt-get install -y dos2unix && dos2unix /tmp/bootstrap_vm_portable.sh && chmod +x /tmp/bootstrap_vm_portable.sh && sudo /tmp/bootstrap_vm_portable.sh"

# Test
# on VM
dig @127.0.0.1 dnsproof.org TXT
dig @127.0.0.1 dnsproof.org NS
dig @127.0.0.1 ns1.dnsproof.org A

IPVM=136.115.36.6
# on outside
dig @$IPVM dnsproof.org TXT +short
dig @$IPVM ns1.dnsproof.org A +short

#-------------------------------------------------
# copy agent files to VM
bash push-dnsagent.sh dns-vm

#-------------------------------------------------
# test to see if port 8000 is open to outside
curl http://$IPVM:8000/docs

#-------------------------------------------------
# Send JSON zone file to the internal FastAPI endpoint '/push'
curl -X POST http://$IPVM:8000/internal/dns/push \
  -H "Content-Type: application/json" \
  -d @json/dnsproof.org.json

# check DNS records
dig @$IPVM dnsproof.org MX +short

#-------------------------------------------------
# Bootstrap startup with Debian
VMNAME=dns-vm
PROJECT=nameserver-platform
ZONE=us-central1-a
IPVM=136.114.103.240

tar czf dnsagent_bundle.tar.gz \
  bootstrap_vm_portable.sh \
  dnsproof/*.py

gcloud compute instances create $VMNAME \
  --zone=$ZONE \
  --machine-type=e2-micro \
  --image-family=debian-13 \
  --image-project=debian-cloud \
  --address=dns-ip \
  --tags=agent-vm,dns-server \
  --boot-disk-size=10GB \
  --scopes=compute-rw

gcloud compute scp dnsagent_bundle.tar.gz $VMNAME:/tmp/ --zone=$ZONE

gcloud compute ssh $VMNAME --zone=$ZONE --command "
  cd /tmp && \
  tar xzf dnsagent_bundle.tar.gz && \
  sudo apt-get update && \
  sudo apt-get install -y dos2unix && \
  dos2unix bootstrap_vm_portable.sh && \
  chmod +x bootstrap_vm_portable.sh && \
  sudo ./bootstrap_vm_portable.sh 'dEcartes2026' && \
  sudo mkdir -p /srv/dns && \
  sudo mv dnsproof/*.py /srv/dns/ && \
  sudo chown root:root /srv/dns/*.py && \
  sudo systemctl restart dnsagent && \
  sudo rm -rf /tmp/dnsproof /tmp/bootstrap_vm_portable.sh /tmp/*.tar.gz
"