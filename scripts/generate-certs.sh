#!/bin/bash
set -euo pipefail

# CrabTrap - CA Certificate Generation Script
# This script generates a self-signed CA certificate for TLS interception

# Get the project root (one level up from scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERT_DIR="$PROJECT_ROOT/certs"

# Create certs directory if it doesn't exist
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "=========================================="
echo "CrabTrap - CA Certificate Setup"
echo "=========================================="
echo ""

# Step 1: Generate CA certificate
echo "Step 1: Generating CA certificate..."
echo ""

echo "  → Generating CA private key (4096 bit)..."
openssl genrsa -out ca.key 4096 2>/dev/null

echo "  → Generating CA certificate (valid 10 years)..."
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=US/ST=California/L=San Francisco/O=CrabTrap/CN=CrabTrap CA" 2>/dev/null

echo "  → Setting permissions..."
chmod 600 ca.key
chmod 644 ca.crt

echo ""
echo "✓ CA certificate generated successfully!"
echo ""
echo "  Certificate: $CERT_DIR/ca.crt"
echo "  Private key: $CERT_DIR/ca.key"
echo ""

# Step 2: Install CA certificate (OPTIONAL)
echo "Step 2: Installing CA certificate (OPTIONAL)..."
echo ""

if [[ "${CI:-}" == "true" || ! -t 0 ]]; then
    echo "CI/non-interactive mode detected; skipping certificate installation."
    echo ""
    echo "=========================================="
    echo "Setup Complete!"
    echo "=========================================="
    echo ""
    echo "For Node.js applications, you can also use:"
    echo "  export NODE_EXTRA_CA_CERTS=$CERT_DIR/ca.crt"
    echo ""
    echo "Next steps:"
    echo "  1. Build the gateway: make build"
    echo "  2. Start the gateway: make run"
    echo "  3. Test the proxy: ./test-proxy.sh"
    echo ""
    exit 0
fi

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    echo "Detected: macOS"
    echo ""
    echo "NOTE: System-wide installation is OPTIONAL for testing!"
    echo ""
    echo "You can test without system installation using:"
    echo "  curl -x http://localhost:8080 --cacert certs/ca.crt https://httpbin.org/get"
    echo ""
    echo "Or for Node.js apps:"
    echo "  export NODE_EXTRA_CA_CERTS=$(pwd)/certs/ca.crt"
    echo ""
    echo "System installation is only needed if you want ALL applications"
    echo "to automatically trust the proxy (requires administrator privileges)."
    echo ""

    # Ask for confirmation
    read -p "Install CA certificate system-wide? (y/n): " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "  → Removing old certificate (if exists)..."
        security delete-certificate -c "CrabTrap CA" 2>/dev/null || true

        echo "  → Installing certificate with full trust in system keychain..."
        if sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT_DIR/ca.crt"; then
            echo ""
            echo "✓ Certificate installed successfully!"
            echo ""
            echo "Verification:"
            security find-certificate -c "CrabTrap CA" -p | openssl x509 -noout -subject 2>/dev/null
        else
            echo ""
            echo "⚠ Failed to install certificate in system keychain."
            echo "Trying user keychain instead..."
            security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain "$CERT_DIR/ca.crt" || true
        fi
    else
        echo ""
        echo "⚠ Skipping automatic installation."
        echo ""
        echo "To install manually later, run:"
        echo "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERT_DIR/ca.crt"
    fi

elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    echo "Detected: Linux"
    echo ""
    echo "The CA certificate needs to be installed in your system's trusted certificates."
    echo "This requires root privileges."
    echo ""

    read -p "Install CA certificate now? (y/n): " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "  → Copying certificate to /usr/local/share/ca-certificates/..."
        sudo cp "$CERT_DIR/ca.crt" /usr/local/share/ca-certificates/openclaw-gateway.crt

        echo "  → Updating CA certificates..."
        sudo update-ca-certificates

        echo ""
        echo "✓ Certificate installed successfully!"
    else
        echo ""
        echo "⚠ Skipping automatic installation."
        echo ""
        echo "To install manually later, run:"
        echo "  sudo cp $CERT_DIR/ca.crt /usr/local/share/ca-certificates/openclaw-gateway.crt"
        echo "  sudo update-ca-certificates"
    fi

else
    # Windows or other
    echo "Detected: $OSTYPE"
    echo ""
    echo "⚠ Automatic installation not supported on this platform."
    echo ""
    echo "Please install the CA certificate manually:"
    echo "  Certificate location: $CERT_DIR/ca.crt"
    echo ""
    echo "Windows: Import into 'Trusted Root Certification Authorities'"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "For Node.js applications, you can also use:"
echo "  export NODE_EXTRA_CA_CERTS=$CERT_DIR/ca.crt"
echo ""
echo "Next steps:"
echo "  1. Build the gateway: make build"
echo "  2. Start the gateway: make run"
echo "  3. Test the proxy: ./test-proxy.sh"
echo ""
