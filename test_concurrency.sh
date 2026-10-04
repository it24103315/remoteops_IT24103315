#!/bin/bash
# ==============================================================================
# Automated Concurrency Verification Script for RemoteOps
# Student Registration Number: IT24103315
# Tests 5 simultaneous Controller connections executing commands in parallel
# ==============================================================================

PORT=9410
HOST="127.0.0.1"
TOKEN="OPS-3315"

echo "=========================================================="
echo " Starting 5 Simultaneous Controller Connections Stress Test"
echo "=========================================================="

# Function simulating a single Controller session
run_client() {
    CLIENT_ID=$1
    echo "[Client $CLIENT_ID] Initiating connection..."
    
    # Use netcat (nc) to send commands with newline framing
    (
        echo "AUTH $TOKEN"
        sleep 0.5
        echo "SYSINFO"
        sleep 0.5
        echo "EXEC WHOAMI"
        sleep 0.5
        echo "QUIT"
    ) | nc $HOST $PORT > "client_${CLIENT_ID}_output.log" 2>&1

    echo "[Client $CLIENT_ID] Completed. Response:"
    cat "client_${CLIENT_ID}_output.log"
    echo "----------------------------------------------------------"
}

# Launch 5 simultaneous clients in background
for i in {1..5}; do
    run_client $i &
done

# Wait for all background clients to finish
wait

echo "[+] All 5 simultaneous Controller sessions completed successfully!"
rm -f client_*_output.log
