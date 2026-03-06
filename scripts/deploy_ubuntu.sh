#!/bin/bash
set -e

echo "=========================================================="
echo "    CTI MCP Server - Ubuntu 24.04 Production Deployment   "
echo "=========================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root or with sudo"
  exit 1
fi

INSTALL_DIR="/opt/cti-mcp-server"
REPO_URL="https://github.com/SecureAI-Team/cti-mcp-server.git"

echo "[1/5] Installing system dependencies (Docker & Git)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -yq
apt-get install -yq git curl openssl ca-certificates xz-utils

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "      Installing Docker Engine via apt..."
    apt-get install -yq docker.io docker-compose-v2
    systemctl enable --now docker
else
    echo "      Docker is already installed."
fi

echo "[2/5] Fetching repository to $INSTALL_DIR..."
if [ -d "$INSTALL_DIR" ]; then
    echo "      Directory $INSTALL_DIR already exists, fetching latest changes..."
    cd "$INSTALL_DIR"
    git reset --hard HEAD
    git pull origin main
else
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo "[3/5] Configuring Environment and Security Tokens..."
if [ ! -f .env ]; then
    cp .env.example .env
fi

# Generate a strong token if we have default placeholder in nginx
if grep -q "your-secret-mcp-token" nginx/nginx.conf; then
    NEW_TOKEN=$(openssl rand -hex 24)
    # Update .env
    sed -i "s/MCP_AUTH_TOKEN=.*/MCP_AUTH_TOKEN=$NEW_TOKEN/g" .env
    
    # Update nginx.conf map block to use the random token
    sed -i "s/your-secret-mcp-token/$NEW_TOKEN/g" nginx/nginx.conf
    
    echo "      [+] Generated secure MCP_AUTH_TOKEN: $NEW_TOKEN"
    echo "          (Save this token! You will need it to connect AI agents)"
else
    echo "      Custom MCP_AUTH_TOKEN already configured."
    NEW_TOKEN=$(grep MCP_AUTH_TOKEN .env | cut -d '=' -f2 || echo "UNKNOWN")
fi

# Ensure correct permissions for mounted directories (matches appuser uid 1000)
mkdir -p logs .mitre_cache
chown -R 1000:1000 logs .mitre_cache

echo "[4/5] Building and Starting Docker Containers..."
# docker-compose v2 is usually accessed via 'docker compose'
docker compose -f docker-compose.prod.yml up -d --build

echo "=========================================================="
echo " ✅ Deployment Successful!"
echo "----------------------------------------------------------"
PUBLIC_IP=$(curl -s ifconfig.me || echo "127.0.0.1")
echo " 🌐 Service is running on http://${PUBLIC_IP}:80"
echo ""
echo " 🔑 To connect your AI Agent (e.g. LangChain, Dify), use this header:"
echo "    Authorization: Bearer ${NEW_TOKEN}"
echo ""
echo " 🔧 Adjust API Keys (Virustotal, OTX):"
echo "    nano $INSTALL_DIR/.env"
echo "    docker compose -f $INSTALL_DIR/docker-compose.prod.yml restart cti-mcp"
echo ""
echo " 📝 To check logs:"
echo "    cd $INSTALL_DIR && docker compose -f docker-compose.prod.yml logs -f"
echo "=========================================================="
