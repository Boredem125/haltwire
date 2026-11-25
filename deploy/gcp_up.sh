#!/usr/bin/env bash
# Tripwire -- GCP VM provisioning script
#
# Creates all GCP resources for a single-VM deployment.
# Review and edit variables before running.  NOT idempotent -- only run once.
#
# Prerequisites:
#   - gcloud CLI authenticated (`gcloud auth login`)
#   - A GCP project with billing enabled
#   - Compute Engine API enabled
#
# Usage:
#   chmod +x gcp_up.sh
#   ./gcp_up.sh

set -euo pipefail

# ===== EDIT THESE =====
PROJECT_ID="${GCP_PROJECT_ID:?Set GCP_PROJECT_ID}"
REGION="asia-south1"
ZONE="asia-south1-a"
VM_NAME="tripwire"
IP_NAME="tripwire-ip"
MACHINE_TYPE="e2-standard-2"
DISK_SIZE="30GB"
FW_RULE_HTTP="allow-tripwire-http-https"
FW_RULE_SSH="allow-tripwire-ssh"
# L7: Founder's IP for SSH access (CIDR). REQUIRED -- exit if unset.
FOUNDER_SSH_CIDR="${FOUNDER_SSH_CIDR:?FOUNDER_SSH_CIDR must be set (e.g. 203.0.113.5/32). Do not use 0.0.0.0/0.}"
# =======================

echo "==> Project: ${PROJECT_ID}"
gcloud config set project "${PROJECT_ID}"

# --- 1. Reserve a static external IP ---
echo "==> Reserving static IP ${IP_NAME}..."
gcloud compute addresses create "${IP_NAME}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    || echo "  (already exists, continuing)"

ARENA_IP=$(gcloud compute addresses describe "${IP_NAME}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --format='value(address)')
echo "  Static IP: ${ARENA_IP}"

ARENA_DOMAIN=$(echo "${ARENA_IP}" | tr '.' '-').sslip.io
echo "  Domain:    ${ARENA_DOMAIN}"

# --- 2. Firewall rules ---
echo "==> Creating firewall rule ${FW_RULE_HTTP} (80/443 from anywhere)..."
gcloud compute firewall-rules create "${FW_RULE_HTTP}" \
    --allow=tcp:80,tcp:443 \
    --target-tags=http-server \
    --direction=INGRESS \
    --project="${PROJECT_ID}" \
    || echo "  (already exists, continuing)"

echo "==> Creating firewall rule ${FW_RULE_SSH} (22 from ${FOUNDER_SSH_CIDR})..."
gcloud compute firewall-rules create "${FW_RULE_SSH}" \
    --allow=tcp:22 \
    --source-ranges="${FOUNDER_SSH_CIDR}" \
    --target-tags=http-server \
    --direction=INGRESS \
    --project="${PROJECT_ID}" \
    || echo "  (already exists, continuing)"

# --- 3. Create VM (no service account, no scopes) ---
# The startup script goes through a file: multi-line arguments do not survive
# gcloud.cmd on Windows.
STARTUP_FILE="$(mktemp)"
cat > "${STARTUP_FILE}" <<'STARTUP'
#!/bin/bash
set -e
# Install Docker from Docker official apt repo (docker-compose-v2 included)
apt-get update
apt-get install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker
usermod -aG docker $(logname 2>/dev/null || echo ubuntu)
echo "Docker installed OK"
STARTUP
echo "==> Creating VM ${VM_NAME}..."
gcloud compute instances create "${VM_NAME}" \
    --zone="${ZONE}" \
    --machine-type="${MACHINE_TYPE}" \
    --image-family=ubuntu-2404-lts-amd64 \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size="${DISK_SIZE}" \
    --boot-disk-type=pd-balanced \
    --tags=http-server \
    --address="${ARENA_IP}" \
    --no-service-account \
    --no-scopes \
    --project="${PROJECT_ID}" \
    --metadata-from-file=startup-script="$(cygpath -w "${STARTUP_FILE}" 2>/dev/null || echo "${STARTUP_FILE}")"

echo ""
echo "======================================"
echo "  VM created: ${VM_NAME}"
echo "  IP:         ${ARENA_IP}"
echo "  Domain:     https://${ARENA_DOMAIN}"
echo "======================================"
echo ""
echo "Next steps:"
echo "  1. Wait ~2 min for startup script to install Docker."
echo "  2. Upload the repo:"
echo "       cd /path/to/haltwire"
echo "       tar czf /tmp/tripwire-deploy.tar.gz \\"
echo "           --exclude='.git' --exclude='.venv' --exclude='__pycache__' \\"
echo "           --exclude='node_modules' --exclude='tests' --exclude='.mypy_cache' \\"
echo "           pyproject.toml src/ arena/ deploy/"
echo "       gcloud compute scp /tmp/tripwire-deploy.tar.gz ${VM_NAME}:~ --zone=${ZONE}"
echo ""
echo "  3. SSH and deploy:"
echo "       gcloud compute ssh ${VM_NAME} --zone=${ZONE}"
echo "       mkdir -p ~/tripwire && cd ~/tripwire"
echo "       tar xzf ~/tripwire-deploy.tar.gz"
echo "       cd deploy && cp .env.example .env"
echo "       # Edit .env: add keys + ARENA_DOMAIN=${ARENA_DOMAIN}"
echo "       docker compose up -d --build"
echo ""
echo "  4. Smoke test:"
echo "       curl -s https://${ARENA_DOMAIN}/api/state | head"
echo ""
echo "  5. Teardown (when done):"
echo "       gcloud compute instances delete ${VM_NAME} --zone=${ZONE}"
echo "       gcloud compute addresses delete ${IP_NAME} --region=${REGION}"
echo "       gcloud compute firewall-rules delete ${FW_RULE_HTTP}"
echo "       gcloud compute firewall-rules delete ${FW_RULE_SSH}"
