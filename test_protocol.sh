#!/bin/bash
# ==============================================================================
# Comprehensive Protocol Test Suite for RemoteOps
# Student Registration Number: IT24103315
# Tests Authentication Gate, Telemetry, Whitelist Execution, and Error States
# ==============================================================================

PORT=9410
HOST="127.0.0.1"
TOKEN="OPS-3315"

echo "=========================================================="
echo " Running Automated Protocol Compliance Test Suite"
echo "=========================================================="

# Test 1: Unauthenticated command rejection
echo -n "[Test 1] Unauthenticated SYSINFO rejection: "
RESP=$(echo -e "SYSINFO\nQUIT" | nc $HOST $PORT | head -n 1)
if [[ "$RESP" =~ "ERR 001 AUTH_REQUIRED" ]]; then echo "PASSED ($RESP)"; else echo "FAILED ($RESP)"; fi

# Test 2: Invalid token rejection
echo -n "[Test 2] Invalid token rejection: "
RESP=$(echo -e "AUTH BAD_TOKEN\nQUIT" | nc $HOST $PORT | head -n 1)
if [[ "$RESP" =~ "ERR 001 AUTH_FAILED" ]]; then echo "PASSED ($RESP)"; else echo "FAILED ($RESP)"; fi

# Test 3: Valid authentication
echo -n "[Test 3] Valid token authentication: "
RESP=$(echo -e "AUTH $TOKEN\nQUIT" | nc $HOST $PORT | head -n 1)
if [[ "$RESP" =~ "OK AUTHENTICATED" ]]; then echo "PASSED ($RESP)"; else echo "FAILED ($RESP)"; fi

# Test 4: Whitelist execution (WHOAMI)
echo -n "[Test 4] Whitelisted EXEC WHOAMI: "
RESP=$(echo -e "AUTH $TOKEN\nEXEC WHOAMI\nQUIT" | nc $HOST $PORT | sed -n '2p')
if [[ "$RESP" =~ "OK EXEC_RESULT" ]]; then echo "PASSED ($RESP)"; else echo "FAILED ($RESP)"; fi

# Test 5: Disallowed command rejection
echo -n "[Test 5] Unauthorized EXEC command rejection: "
RESP=$(echo -e "AUTH $TOKEN\nEXEC rm\nQUIT" | nc $HOST $PORT | sed -n '2p')
if [[ "$RESP" =~ "ERR 002 COMMAND_NOT_ALLOWED" ]]; then echo "PASSED ($RESP)"; else echo "FAILED ($RESP)"; fi

echo "=========================================================="
echo " All automated protocol compliance test cases completed!"
echo "=========================================================="
