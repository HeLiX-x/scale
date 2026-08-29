#!/usr/bin/env bash

PEER1="100.64.174.238" # Airtel WiFi (WSL)
PEER2="100.64.61.181"   # Jio 4G (Arch Linux)

run_test() {
    local target=$1
    local name=$2
    
    echo "=========================================================="
    echo "▶ Benchmarking: $name ($target)"
    echo "=========================================================="
    
    echo "1. Running 50-Packet Loss & Jitter Test..."
    ping_out=$(ping -c 50 -i 0.2 -q "$target" 2>&1)
    
    loss=$(echo "$ping_out" | grep -oP '\d+(?=% packet loss)')
    stats=$(echo "$ping_out" | tail -1 | awk -F '/' '{print $4, $5, $6, $7}')
    read -r min avg max mdev <<< "$stats"
    
    echo "2. Running WireGuard 1420 MTU Full Payload Test (1392 bytes)..."
    mtu_out=$(ping -c 10 -s 1392 -i 0.2 -q "$target" 2>&1)
    mtu_loss=$(echo "$mtu_out" | grep -oP '\d+(?=% packet loss)')
    
    echo ""
    echo "--- RESULTS FOR $name ---"
    echo "  Packet Loss:      $loss%"
    echo "  Avg Latency:      ${avg} ms"
    echo "  Min / Max:        ${min} ms / ${max} ms"
    echo "  Jitter (mdev):    ${mdev} ms"
    echo "  1420 MTU Loss:    $mtu_loss%"
    echo ""
}

echo "Starting Scale Mesh VPN Benchmarks..."
echo "Local IP: $(scale status 2>/dev/null | grep 'Overlay IP' | awk '{print $3}')"
echo ""

run_test "$PEER1" "Airtel Home WiFi (Windows WSL)"
run_test "$PEER2" "Jio 4G (Arch Linux)"

echo "=========================================================="
echo "✔ All benchmarks completed!"
echo "=========================================================="
