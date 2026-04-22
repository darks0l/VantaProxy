# Vanta

[![HTTP Proxy](https://img.shields.io/badge/http%20proxy-mitm%20gateway-2e86de?style=flat-square&logo=shield)](https://github.com/darks0l/VantaProxy)
[![Go](https://img.shields.io/badge/go-1.26-blue?style=flat-square&logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](./LICENSE)
[![Built with teeth](https://img.shields.io/badge/built%20with-teeth%20🌑-black?style=flat-square)](https://darksol.net)

![Vanta Banner](assets/darksol-banner.png)

> HTTP proxy with teeth. Built by Darksol.

An HTTP/HTTPS proxy that sits between AI agents and external APIs, evaluating every outbound request against security policies before it reaches the internet. Inspired by [CrabTrap](https://github.com/brexhq/CrabTrap) — but rebuilt from the ground up for the web3 threat model, with deterministic guardrails that don't depend on the LLM judge alone.

If you run AI agents that touch DeFi protocols, RPC endpoints, or anything on-chain — Vanta gives you teeth. It intercepts every outbound request, runs it through a layered filter stack (static rules → web3 guards → LLM judge), and either forwards it or kills it with a reason logged to disk.

**Key features:**
- **Web3Rules engine** — deterministic, judge-independent protection: chain enforcement, RPC URL validation (blocks IPs, typosquatted providers), contract address denylist, ETH value thresholds, gas price limits
- **RPC health checker** — probes all configured RPCs periodically, detects chain ID mismatches, marks unhealthy endpoints
- **NonceGuard + ValueGuard** — detects nonce collisions, nonce gaps, and unexpected ETH transfers before they reach the mempool
- **Bankr LLM gateway** — per-request policy evaluation routing through OpenAI, Anthropic, Ollama, or OpenRouter with automatic fallback chains
- **Static rules** — URL pattern allowlist/denylist runs before the judge, for instant allow/deny on known patterns
- **Full audit trail** — every decision logged with request/response bodies

## Quickstart

```bash
# Clone
git clone https://github.com/darks0l/VantaProxy.git
cd VantaProxy

# Configure
cp config/gateway.yaml.example config/gateway.yaml
# Edit config/gateway.yaml and set your RPC URLs and LLM provider

# Run with Docker
docker compose up -d

# Or run locally
go build -o vantad .
./vantad --config config/gateway.yaml
```

## Web3 Security Configuration

Vanta's web3 guards are configured in `gateway.yaml`:

```yaml
web3:
  enabled: true

  # RPC endpoints to guard
  rpcs:
    - url: https://eth.llamarpc.com
      chain_id: 1                   # ethereum mainnet
      allowed_chains: [1]           # agent can only interact with mainnet via this RPC
      value_warn_eth: 0.1          # log if agent sends >0.1 ETH
      value_deny_eth: 1.0          # block if agent tries to send >1 ETH
      max_gas_gwei: 200            # block if gas price spikes above 200 gwei
      max_nonce_gap: 5             # warn if nonce gap > 5 (possible duplication)

    - url: https://base.llamarpc.com
      chain_id: 8453                # base
      allowed_chains: [8453, 1]    # can also bridge to mainnet
      value_deny_eth: 2.0

  # Global contract denylist (known drainer/honeypot addresses)
  deny_contracts:
    - "0xAbCdEf1234567890..."
    - "0xFEDCBA0987654321..."

  # Additional chains the agent can interact with (globally)
  allowed_chains:
    - 1        # Ethereum
    - 8453    # Base
    - 42161   # Arbitrum
    - 137     # Polygon
```

## LLM Judge Configuration

The LLM judge evaluates requests that pass the static and web3 guards. It supports multiple providers:

```yaml
llm_judge:
  enabled: true
  provider: "bankr"       # bankr | anthropic | openai | bedrock-anthropic
  bankr_api_key: "${BANKR_API_KEY}"
  bankr_url: "http://localhost:18789"
  eval_model: "anthropic/claude-opus-4-6"
  fast_model: "anthropic/claude-haiku-4-6"
```

For local-model-only deployment (no external API calls):

```yaml
llm_judge:
  enabled: true
  provider: "bankr"
  bankr_api_key: "local"
  bankr_url: "http://localhost:18789"
  eval_model: "ollama/gemma4:26b"
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  AI Agent   │────▶│  Vanta Proxy │────▶│  Static Rules   │────▶│   Web3 Rules    │
│             │     │   (MITM)     │     │  (URL allow/    │     │  (chain, RPC,   │
│             │     │              │     │   deny)          │     │   contract,     │
│             │     │              │     │                 │     │   value)        │
└─────────────┘     └──────────────┘     └─────────────────┘     └────────┬────────┘
                                                                           │
                              ┌────────────────────────────────────────────┘
                              ▼
                    ┌──────────────────┐
                    │   LLM Judge      │
                    │  (Bankr gateway) │
                    │  OpenAI/Anthropic│
                    │  Ollama/Local    │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  SQLite/Postgres  │
                    │  (audit log)      │
                    └──────────────────┘
```

## Guard Stack

Requests flow through layers — any layer can deny:

1. **Static rules** — URL patterns, host allowlist/denylist
2. **Web3Rules** (if web3 enabled):
   - Chain enforcement (does the RPC's chain_id match what the agent is trying to do?)
   - RPC URL validation (blocks direct IPs, infura/llamarpc typosquats)
   - Contract denylist (known drainers, honeypots)
   - Value guard (ETH amount thresholds per RPC)
   - Gas price guard (blocks during MEV/sandwich spikes)
   - NonceGuard (detects duplicate nonces, gap anomalies)
3. **LLM Judge** — full request context, policy prompt, allow/deny with reason

## Development

```bash
# Build the web UI
cd web && npm install && npm run build && cd ..

# Build the Go binary
go build -o vantad ./cmd/gateway

# Run tests
make test

# Run with dev mode (live web UI reload)
go run ./cmd/gateway --dev
```

## Inspiration

Vanta is inspired by [CrabTrap](https://github.com/brexhq/CrabTrap) by Brex — the original MITM proxy for AI agent security. Vanta extends the same core idea (intercept, evaluate, allow/deny) with a web3-first threat model, deterministic web3-specific guardrails, and the Bankr LLM gateway for multi-provider routing.

## License

MIT License. Built with teeth. 🌑
