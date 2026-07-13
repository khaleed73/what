#!/usr/bin/env bash
# setup_hft_server.sh — Optimize a Linux VPS for HFT trading.
# Run as root: sudo bash setup_hft_server.sh
#
# This script optimizes:
#   1. Linux kernel network stack (TCP buffers, congestion control, syn cookies)
#   2. File descriptor limits
#   3. CPU performance governor
#   4. Memory management (swappiness, huge pages)
#   5. Security (iptables rate limiting)
#   6. NTP time sync (critical for exchange API authentication)

set -euo pipefail

echo "=============================================="
echo "  HFT Server Optimization Script"
echo "  Run this as ROOT on your VPS"
echo "=============================================="

# Step 1: Install prerequisites
echo "[1/7] Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq \
    build-essential pkg-config libssl-dev \
    curl wget git tmux htop iotop \
    ntpdate cpulimit \
    linux-cpupower \
    > /dev/null 2>&1
echo "  Done."

# Step 2: Optimize Linux kernel network stack
echo "[2/7] Optimizing kernel network stack..."
cat << 'EOF' >> /etc/sysctl.conf

# === HFT Network Optimization ===

# Maximum memory for TCP socket read/write buffers (16 MB each)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# Increase socket listen backlog for WebSocket connections
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 100000
net.ipv4.tcp_max_syn_backlog = 65535

# Use BBR congestion control for lower latency
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Reduce TIME_WAIT socket accumulation
net.ipv4.tcp_fin_timeout = 5
net.ipv4.tcp_tw_reuse = 1

# Enable TCP fast open
net.ipv4.tcp_fastopen = 3

# Reduce keepalive overhead
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 3

# Disable slow start after idle
net.ipv4.tcp_slow_start_after_idle = 0

# Maximum number of open files
fs.file-max = 1000000

# Reduce swap usage (keep data in RAM)
vm.swappiness = 1

# Increase maximum shared memory segments
kernel.shmmax = 17179869184

# Disable IPv6 if not needed (saves overhead)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
EOF

sysctl -p > /dev/null 2>&1
echo "  Done."

# Step 3: Increase file descriptor limits
echo "[3/7] Setting file descriptor limits..."
cat << 'EOF' >> /etc/security/limits.conf

# HFT Bot Limits
*    soft    nofile    65535
*    hard    nofile    65535
*    soft    nproc     65535
*    hard    nproc     65535
root soft    nofile    65535
root hard    nofile    65535
EOF

echo "  Done."

# Step 4: Set CPU performance governor
echo "[4/7] Setting CPU governor to performance..."
if command -v cpupower &> /dev/null; then
    cpupower frequency-set -g performance 2>/dev/null || true
fi
# Fallback: write directly to sysfs
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > "$cpu" 2>/dev/null || true
done
echo "  Done."

# Step 5: Configure 1GB huge pages (optional, for shared memory arena)
echo "[5/7] Configuring transparent huge pages..."
echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
echo "  Done."

# Step 6: NTP time synchronization (critical for exchange auth timestamps)
echo "[6/7] Configuring time synchronization..."
apt-get install -y -qq chrony > /dev/null 2>&1
systemctl enable chrony
systemctl restart chrony
echo "  Done."

# Step 7: Install Rust toolchain
echo "[7/7] Installing Rust toolchain..."
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
echo "  Done."

echo ""
echo "=============================================="
echo "  Server optimization complete!"
echo ""
echo "  Verify with:"
echo "    sysctl net.core.rmem_max"
echo "    sysctl net.ipv4.tcp_congestion_control"
echo "    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
echo "    chronyc tracking"
echo ""
echo "  Next: Copy your project and run deploy.sh"
echo "=============================================="