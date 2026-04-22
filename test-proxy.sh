#!/bin/bash
set -e

# CrabTrap - Test Script
# This script demonstrates the proxy functionality

PROXY_URL="http://localhost:8080"
ADMIN_URL="http://localhost:8081"
CA_CERT="./certs/ca.crt"

echo "==================================="
echo "CrabTrap - Test Script"
echo "==================================="
echo ""

# Check if gateway is running
if ! curl -s --max-time 1 "$ADMIN_URL/health" > /dev/null 2>&1; then
    echo "Error: Gateway is not running on port 8080/8081"
    echo "Please start the gateway first: ./gateway -config config/gateway.yaml"
    exit 1
fi

echo "✓ Gateway is running"
echo ""

# Test 1: READ operation (should pass immediately)
echo "Test 1: READ operation (GET request)"
echo "--------------------------------------"
echo "Making GET request to httpbin.org/get..."
START=$(date +%s)
curl -x "$PROXY_URL" --cacert "$CA_CERT" -s https://httpbin.org/get | jq -r '.url' || echo "Request failed"
END=$(date +%s)
DURATION=$((END - START))
echo "✓ Request completed in ${DURATION}s (should be fast)"
echo ""

# Test 2: WRITE operation (should block and require approval)
echo "Test 2: WRITE operation (POST request)"
echo "---------------------------------------"
echo "Making POST request to httpbin.org/post..."
echo "This request will BLOCK and wait for approval."
echo ""
echo "In another terminal, run:"
echo "  curl http://localhost:8081/admin/approvals"
echo "  curl -X POST http://localhost:8081/admin/approvals/{request_id}/approve"
echo ""
echo "Waiting for approval..."

# Make POST request in background
(
    sleep 2
    curl -x "$PROXY_URL" --cacert "$CA_CERT" -s -X POST https://httpbin.org/post \
        -H "Content-Type: application/json" \
        -d '{"test": "data", "message": "Hello from CrabTrap"}' \
        > /tmp/openclaw-test-response.txt 2>&1
) &
POST_PID=$!

# Wait a bit and show pending approvals
sleep 3
echo ""
echo "Pending approvals:"
curl -s "$ADMIN_URL/admin/approvals" | jq '.'
echo ""

# Get the request ID
REQUEST_ID=$(curl -s "$ADMIN_URL/admin/approvals" | jq -r '.requests[0].id // empty')

if [ -z "$REQUEST_ID" ]; then
    echo "No pending requests found. The request may have timed out."
    kill $POST_PID 2>/dev/null || true
    exit 1
fi

echo "Found pending request: $REQUEST_ID"
echo ""

# Ask user if they want to auto-approve
read -p "Auto-approve this request? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Approving request..."
    curl -s -X POST "$ADMIN_URL/admin/approvals/$REQUEST_ID/approve" | jq '.'
    echo ""
    echo "✓ Request approved"

    # Wait for the POST request to complete
    wait $POST_PID

    if [ -f /tmp/openclaw-test-response.txt ]; then
        echo ""
        echo "Response:"
        cat /tmp/openclaw-test-response.txt | jq -r '.url' || echo "Request completed"
        rm /tmp/openclaw-test-response.txt
    fi

    echo ""
    echo "Test 3: Cache test (same POST request)"
    echo "---------------------------------------"
    echo "Making the exact same POST request again..."
    echo "This should auto-approve from cache (fast)..."
    START=$(date +%s)
    curl -x "$PROXY_URL" --cacert "$CA_CERT" -s -X POST https://httpbin.org/post \
        -H "Content-Type: application/json" \
        -d '{"test": "data", "message": "Hello from CrabTrap"}' | jq -r '.url' || echo "Request failed"
    END=$(date +%s)
    DURATION=$((END - START))
    echo "✓ Request completed in ${DURATION}s (should be fast, from cache)"
else
    echo "Skipping approval. Killing test request."
    kill $POST_PID 2>/dev/null || true
fi

echo ""
echo "==================================="
echo "Tests complete!"
echo "==================================="
echo ""
echo "Check the audit logs for details:"
echo "  cat audit.log | jq '.'"
echo ""
echo "View cache status:"
echo "  curl http://localhost:8081/health | jq '.'"
echo ""
