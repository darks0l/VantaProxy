# Troubleshooting Guide

## TLS Certificate Errors

### Error: "TLS handshake failed: remote error: tls: unknown certificate"

This means the client doesn't trust the proxy's CA certificate.

#### Quick Diagnosis

```bash
# Check if CA cert is installed
security find-certificate -c "CrabTrap CA"

# Check if CA cert exists
ls -la certs/ca.crt certs/ca.key

# Verify CA cert is valid
openssl x509 -in certs/ca.crt -text -noout | head -20
```

#### Solution 1: Fix Certificate Trust (Recommended)

Run the trust fix script:

```bash
make fix-trust
```

This will:
1. Remove any old certificates
2. Install the CA cert system-wide with full trust
3. Verify installation

#### Solution 2: Use --cacert Flag (Testing Only)

For curl:
```bash
curl -v -x http://localhost:8080 --cacert certs/ca.crt https://httpbin.org/get
```

#### Solution 3: Node.js Applications

Set the CA certificate environment variable:
```bash
export NODE_EXTRA_CA_CERTS=$(pwd)/certs/ca.crt
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Then run your Node.js app
node your-app.js
```

#### Solution 4: Disable Certificate Verification (NOT RECOMMENDED)

For curl (testing only):
```bash
curl -v -x http://localhost:8080 -k https://httpbin.org/get
```

For Node.js (testing only):
```bash
export NODE_TLS_REJECT_UNAUTHORIZED=0
```

**Warning**: Never use this in production!

### Error: "failed to parse CA private key"

The CA key format might be wrong. Regenerate:

```bash
rm certs/ca.key certs/ca.crt
./scripts/generate-certs.sh
make fix-trust
```

## Connection Errors

### Error: "connection refused" on port 8080

Gateway is not running. Start it:
```bash
./gateway -config config/gateway.yaml
```

### Error: "connection refused" on port 8081

Admin API is not running. Check gateway logs for errors.

### Error: Port already in use

```bash
# Find what's using port 8080
lsof -i :8080

# Kill it
kill -9 <PID>

# Or change the port in config/gateway.yaml
```

## Request Not Being Proxied

### Requests bypass the proxy

Make sure proxy environment variables are set:

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Verify
echo $HTTP_PROXY
echo $HTTPS_PROXY
```

### Some apps ignore proxy settings

Some applications don't respect environment variables. Try:

**curl**: Use explicit `-x` flag
```bash
curl -x http://localhost:8080 --cacert certs/ca.crt https://example.com
```

**wget**: Use explicit proxy
```bash
https_proxy=http://localhost:8080 wget --ca-certificate=certs/ca.crt https://example.com
```

## Approval Issues

### LLM judge denying requests unexpectedly

Check the user's assigned policy in the web UI or via the admin API. The LLM judge evaluates all requests (including GETs) against the user's active policy.

If the LLM judge is unavailable, the `llm_judge.fallback_mode` config determines behavior:
- `deny` (default): reject the request
- `passthrough`: allow the request through

### Requests failing with 407

The proxy requires gateway auth. Pass credentials via the proxy URL:
```bash
curl -x http://gat_YOUR_TOKEN:@localhost:8080 https://httpbin.org/get
```

## Testing Issues

### test-proxy.sh fails with certificate error

Run the certificate fix first:
```bash
make fix-trust
```

### Admin API not responding

Make sure admin API is responding:
```bash
curl http://localhost:8081/admin/health
```

If not, check gateway logs for errors.

## macOS Specific Issues

### "Operation not permitted" when installing cert

Use sudo:
```bash
make fix-trust
```

### Certificate installed but still getting errors

Try installing in user keychain instead:
```bash
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain certs/ca.crt
```

Then restart your browser/application.

### "This certificate is not trusted" in browser

1. Open Keychain Access
2. Search for "CrabTrap CA"
3. Double-click the certificate
4. Expand "Trust"
5. Set "When using this certificate" to "Always Trust"
6. Close and enter your password
7. Restart browser

## Linux Specific Issues

### Installing CA certificate

```bash
# Copy cert to system location
sudo cp certs/ca.crt /usr/local/share/ca-certificates/openclaw-gateway.crt

# Update CA certificates
sudo update-ca-certificates

# Verify
ls -la /etc/ssl/certs | grep openclaw
```

### curl still doesn't trust certificate

```bash
# Use explicit CA bundle
curl --cacert certs/ca.crt -x http://localhost:8080 https://example.com
```

## Performance Issues

### High latency on requests

In `llm` mode, every request (including GETs) is evaluated by the LLM judge, which adds latency proportional to the LLM response time. Check:

1. LLM judge timeout setting (`llm_judge.timeout`, default 30s)
2. Network latency to AWS Bedrock
3. Network latency to destination
4. Gateway logs for errors
5. CPU usage: `top -p $(pgrep gateway)`

Consider using `passthrough` mode for testing if LLM latency is not needed.

## Logs and Debugging

### View audit logs

```bash
# Audit log entries go to stdout as JSON lines; operational logs go to stderr
./gateway -config config/gateway.yaml 2>&1 | tee gateway.log

# View in separate terminal
tail -f gateway.log | jq '.'
```

### Enable verbose logging

Set `log_level: debug` in your `config/gateway.yaml`:
```yaml
log_level: debug
```

This enables detailed request/response logging including method, URL, headers, and body.

### Check what requests are being proxied

```bash
# Filter audit logs for specific URL
cat gateway.log | jq 'select(.url | contains("httpbin"))'

# Count requests by method
cat gateway.log | jq -r '.method' | sort | uniq -c
```

## Common Mistakes

### ❌ Forgot to install CA certificate
```bash
# Wrong
curl -x http://localhost:8080 https://example.com
# Error: certificate verify failed

# Right
curl -x http://localhost:8080 --cacert certs/ca.crt https://example.com
# Or install CA cert system-wide
```

### ❌ Using HTTP instead of HTTPS
```bash
# This works but doesn't test TLS interception
curl -x http://localhost:8080 http://example.com

# Test HTTPS to verify TLS interception
curl -x http://localhost:8080 --cacert certs/ca.crt https://example.com
```

### ❌ Forgetting to set proxy environment variables
```bash
# Wrong
curl https://example.com  # Bypasses proxy

# Right
curl -x http://localhost:8080 --cacert certs/ca.crt https://example.com
# Or
export HTTPS_PROXY=http://localhost:8080
curl --cacert certs/ca.crt https://example.com
```

### ❌ Missing gateway auth token
```bash
# Wrong — returns 407
curl -x http://localhost:8080 https://example.com

# Right — include gateway auth token
curl -x http://gat_YOUR_TOKEN:@localhost:8080 --cacert certs/ca.crt https://example.com
```

## Still Having Issues?

1. Check gateway logs for error messages
2. Verify CA certificate is valid: `openssl x509 -in certs/ca.crt -text -noout`
3. Test with a simple GET request first
4. Make sure ports 8080 and 8081 are not blocked by firewall
5. Try regenerating certificates: `rm certs/ca.* && ./scripts/generate-certs.sh`

## Quick Reset

If all else fails:

```bash
# Stop gateway
pkill -f gateway

# Remove old certificates
rm certs/ca.key certs/ca.crt
security delete-certificate -c "CrabTrap CA" 2>/dev/null || true

# Regenerate and reinstall
./scripts/generate-certs.sh
make fix-trust

# Rebuild and restart
make build
./gateway -config config/gateway.yaml
```

## Getting Help

When reporting issues, include:
1. Gateway version/commit
2. Operating system and version
3. Error message from gateway logs
4. Command you're running
5. Output of: `curl http://localhost:8081/admin/health`
