#!/bin/bash
# Nasazení SEZ API na servery 10.84.7.146 a 10.84.7.147
# Použití: ./deploy/push-to-servers.sh
# Nebo s jiným uživatelem: SSH_USER=root ./deploy/push-to-servers.sh

set -e
SSH_USER="${SSH_USER:-$USER}"
SERVERS="10.84.7.146 10.84.7.147"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "=== Vytvářím balíček pro nasazení ==="
# COPYFILE_DISABLE zabrání tvorbě macOS AppleDouble (._*) souborů v tarballu
COPYFILE_DISABLE=1 tar czf /tmp/sez-api-deploy.tar.gz \
  --exclude='.venv' --exclude='__pycache__' --exclude='.git' \
  --exclude='.DS_Store' --exclude='._*' \
  sez_api/ deploy/ requirements.txt pyproject.toml

for host in $SERVERS; do
  echo ""
  echo "=== Nasazuji na $SSH_USER@$host ==="
  scp -o ConnectTimeout=15 /tmp/sez-api-deploy.tar.gz "$SSH_USER@$host:/tmp/" || { echo "SCP selhal pro $host"; continue; }
  ssh "$SSH_USER@$host" "cd /tmp && rm -rf sez-api-deploy && mkdir -p sez-api-deploy && tar xzf sez-api-deploy.tar.gz -C sez-api-deploy && cd sez-api-deploy && [ -f /opt/sez-api/.env ] && cp /opt/sez-api/.env .env 2>/dev/null; sudo ./deploy/install.sh"
  echo "✓ $host hotovo"
done

echo ""
echo "=== Nasazení dokončeno ==="
