#!/usr/bin/env bash
# deploy.sh — Package, transfer, compile, and deploy the HFT arbitrage bot to a remote VPS.
# Usage: ./deploy.sh <VPS_IP> <VPS_USER> <SSH_KEY_PATH>

set -euo pipefail

VPS_IP="${1:?Usage: ./deploy.sh <VPS_IP> <VPS_USER> <SSH_KEY_PATH>}"
VPS_USER="${2:?Usage: ./deploy.sh <VPS_IP> <VPS_USER> <SSH_KEY_PATH>}"
SSH_KEY="${3:-$HOME/.ssh/id_rsa}"

PROJECT_NAME="rust-hft-arb"
REMOTE_DIR="/opt/$PROJECT_NAME"
SERVICE_NAME="rust-arb-bot"

echo "=========================================="
echo "  HFT Arbitrage Bot — Deployment Script"
echo "=========================================="

# Step 1: Package the project (exclude build artifacts)
echo "[1/6] Packaging project..."
TEMP_DIR=$(mktemp -d)
cp -r . "$TEMP_DIR/$PROJECT_NAME"
rm -rf "$TEMP_DIR/$PROJECT_NAME/target"
rm -rf "$TEMP_DIR/$PROJECT_NAME/.git"
rm -f "$TEMP_DIR/$PROJECT_NAME/Cargo.lock"
tar -czf "/tmp/$PROJECT_NAME.tar.gz" -C "$TEMP_DIR" "$PROJECT_NAME"
rm -rf "$TEMP_DIR"
echo "  Package created: /tmp/$PROJECT_NAME.tar.gz"

# Step 2: Transfer to VPS
echo "[2/6] Transferring to $VPS_USER@$VPS_IP..."
scp -i "$SSH_KEY" "/tmp/$PROJECT_NAME.tar.gz" "$VPS_USER@$VPS_IP:/tmp/$PROJECT_NAME.tar.gz"

# Step 3: Extract on VPS
echo "[3/6] Extracting on remote server..."
ssh -i "$SSH_KEY" "$VPS_USER@$VPS_IP" bash -s << 'REMOTE_SCRIPT'
set -euo pipefail
sudo mkdir -p /opt/rust-hft-arb
sudo rm -rf /opt/rust-hft-arb/*
sudo tar -xzf /tmp/rust-hft-arb.tar.gz -C /opt/
sudo chown -R $USER:$USER /opt/rust-hft-arb
echo "  Extracted to /opt/rust-hft-arb"
REMOTE_SCRIPT

# Step 4: Compile with maximum optimizations
echo "[4/6] Compiling with target-cpu=native..."
ssh -i "$SSH_KEY" "$VPS_USER@$VPS_IP" bash -s << 'REMOTE_SCRIPT'
set -euo pipefail
cd /opt/rust-hft-arb
export RUSTFLAGS="-C target-cpu=native"
cargo build --release 2>&1
echo "  Compilation complete: target/release/rust-hft-arb"
REMOTE_SCRIPT

# Step 5: Install systemd service
echo "[5/6] Installing systemd service..."
ssh -i "$SSH_KEY" "$VPS_USER@$VPS_IP" bash -s << 'REMOTE_SCRIPT'
set -euo pipefail
sudo cp /opt/rust-hft-arb/rust-arb-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable rust-arb-bot
echo "  Service installed and enabled"
REMOTE_SCRIPT

# Step 6: Start the service
echo "[6/6] Starting service..."
ssh -i "$SSH_KEY" "$VPS_USER@$VPS_IP" bash -s << 'REMOTE_SCRIPT'
set -euo pipefail
sudo systemctl restart rust-arb-bot
sleep 2
sudo systemctl status rust-arb-bot --no-pager
echo ""
echo "  To view live logs: journalctl -u rust-arb-bot -f --output cat"
REMOTE_SCRIPT

echo ""
echo "=========================================="
echo "  Deployment complete!"
echo "  Monitor: ssh $VPS_USER@$VPS_IP 'journalctl -u $SERVICE_NAME -f --output cat'"
echo "=========================================="

# Cleanup
rm -f "/tmp/$PROJECT_NAME.tar.gz"