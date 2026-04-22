# Quick Start

Get CrabTrap running in under 2 minutes with Docker.

## 1. Create a compose file

Save this as `docker-compose.yml`:

```yaml
services:
  crabtrap:
    image: quay.io/brexhq/crabtrap:latest
    ports:
      - "8080:8080"
      - "8081:8081"
    environment:
      DATABASE_URL: postgres://crabtrap:secret@postgres:5432/crabtrap
    volumes:
      - certs:/app/certs
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_DB: crabtrap
      POSTGRES_USER: crabtrap
      POSTGRES_PASSWORD: secret
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U crabtrap -d crabtrap"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  certs:
  postgres_data:
```

## 2. Start CrabTrap

```bash
docker compose up -d
```

The CA certificate is generated automatically on first run.

- **Proxy**: `localhost:8080`
- **Admin UI**: `localhost:8081`

## 3. Create Admin User and store its token in $web_token bash variable

```
admin_token=$(docker compose exec -it crabtrap ./gateway create-admin-user test-admin \
    | tail -n1 | cut -d" " -f2)
```

## 4. Create Agent User

```
curl -X POST http://localhost:8081/admin/users \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $web_token" \
    -d '{"id": "alice@example.com", "is_admin": false}'
```

## 5. Copy the CA certificate

Copy the auto-generated CA certificate out of the container:

```bash
docker compose cp crabtrap:/app/certs/ca.crt ./ca.crt
```

## 6. Trust the CA certificate

Your agent needs to trust CrabTrap's CA so it can decrypt HTTPS traffic. Pick one approach:

**Option A — per-runtime env var** (scoped, no `sudo` required):

```bash
export NODE_EXTRA_CA_CERTS=$(pwd)/ca.crt       # Node.js
export REQUESTS_CA_BUNDLE=$(pwd)/ca.crt         # Python (requests)
```

**Option B — system trust store** (works for every TLS client on the machine, requires `sudo`):

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca.crt

# Linux (Debian/Ubuntu)
sudo cp ca.crt /usr/local/share/ca-certificates/crabtrap.crt
sudo update-ca-certificates
```

## 7. Point your agent at it

Retrieve the token created for the user

```bash
token=$(curl -s 'http://localhost:8081/admin/users/alice%40example.com' \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $web_token" \
    | jq -r '.channels[] | select(.channel_type == "gateway_auth") | .gateway_auth_token')
```

```bash
export HTTP_PROXY=http://${token}:@localhost:8080
export HTTPS_PROXY=http://${token}:@localhost:8080
```

Test it:

```bash
curl -x http://${token}:@localhost:8080 --cacert ca.crt https://httpbin.org/get
```

## Configuration

Without a config file, CrabTrap starts in **passthrough mode** — all requests are allowed and logged. To enable LLM-based policy enforcement, create a config file:

```yaml
# gateway.yaml
approval:
  mode: llm

llm_judge:
  enabled: true
  provider: bedrock-anthropic
  eval_model: us.anthropic.claude-3-5-haiku-20241022-v1:0
  aws_region: us-west-2

database:
  url: postgres://crabtrap:secret@postgres:5432/crabtrap
```

Mount it in your compose file by adding to `crabtrap.volumes`:

```yaml
- ./gateway.yaml:/app/config/gateway.yaml
```

Then restart: `docker compose up -d`

See [`config/gateway.yaml.example`](config/gateway.yaml.example) for the full reference.

## Development Setup

To build from source (for contributing or customization):

```bash
git clone https://github.com/brexhq/CrabTrap.git
cd CrabTrap
make setup    # generates CA certs + builds binary
make dev      # starts PostgreSQL, backend, and frontend with hot-reload
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow.
