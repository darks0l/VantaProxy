# Vanta

[![HTTP Proxy](https://img.shields.io/badge/http%20proxy-mitm%20gateway-2e86de?style=flat-square&logo=shield)](https://github.com/darks0l/VantaProxy)
[![Go](https://img.shields.io/badge/go-1.26-blue?style=flat-square&logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](./LICENSE)
[![Built with teeth](https://img.shields.io/badge/built%20with-teeth%20🌑-black?style=flat-square)](https://darksol.net)

![Vanta Banner](assets/darksol-banner.png)

> HTTP proxy with teeth. Built by Darksol.

An HTTP/HTTPS proxy that sits between AI agents and external APIs, evaluating every outbound request against security policies before it reaches the internet. Powered by the Bankr LLM gateway for multi-provider routing, model fallback chains, and budget-aware inference.

If you run AI agents that call external services — Slack, Gmail, GitHub, DeFi protocols, RPC endpoints, or anything else — Vanta gives you guardrails. It intercepts every outbound HTTP/HTTPS request, checks it against deterministic rules and an LLM-based policy judge, and either forwards it or blocks it with a reason.

**Key differences from CrabTrap:**
- **Bankr LLM gateway** — routes through OpenAI, Anthropic, Ollama, or OpenRouter with automatic fallback chains and budget guards
- **Web3-native** — static rules for DeFi protocols, RPC endpoints, smart contract interactions, and wallet safety
- **Local-model ready** — runs the judge on your own hardware via Ollama
- **SQLite-first** — zero-infrastructure deployment option

<p align="center">
  <img src="docs/vanta-flow.svg" alt="Vanta request flow" width="800" />
</p>

## Quickstart

```bash
# Clone
git clone https://github.com/darks0l/VantaProxy.git
cd VantaProxy

# Configure
cp config/gateway.yaml.example config/gateway.yaml
# Edit config/gateway.yaml and set your LLM provider + API keys

# Run with Docker
docker compose up -d

# Or run locally
go build -o vantad .
./vantad --config config/gateway.yaml
```

## Configuration

Vanta supports multiple LLM providers. Set `llm_judge.provider` in your config:

```yaml
llm_judge:
  enabled: true
  provider: "bankr"       # bankr | anthropic | openai | bedrock-anthropic
  bankr_api_key: "${BANKR_API_KEY}"
  bankr_url: "http://localhost:18789"
  eval_model: "anthropic/claude-opus-4-6"   # model used for live approval
  fast_model: "anthropic/claude-haiku-4-6"   # model used for policy agent
```

For local-model-only deployment:

```yaml
llm_judge:
  enabled: true
  provider: "bankr"
  bankr_api_key: "local"
  bankr_url: "http://localhost:18789"
  eval_model: "ollama/gemma4:26b"
```

## Web3 Security Rules

Vanta ships with Web3-specific static rules out of the box:

- **RPC endpoint allowlisting** — per-chain (Ethereum, Base, Arbitrum, Optimism, Solana)
- **Known malicious contract detection** — honeypots, scam tokens, bridge exploits
- **Token approval monitoring** — detect unbounded approvals to unknown contracts
- **Flash loan protection** — block known flash loan attack patterns
- **Wallet interaction rules** — raw transaction construction, permit signatures, permit2

Configure Web3 rules in `config/web3-rules.yaml`:

```yaml
allowed_rpc:
  - "https://mainnet.base.org"
  - "https://base-mainnet.g.alchemy.com/v4/${ALCHEMY_API_KEY}"

blocked_contracts:
  - address: "0x..."
    reason: "honeypot token"
    chains: ["ethereum", "base"]

max_approval_value:
  default: "unlimited"  # or specify a uint256 value
  require_explicit_approval_above: "1000000000000000000"  # 1 ETH equivalent
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  AI Agent   │────▶│  Vanta Proxy │────▶│  Static Rules   │
│             │     │   (MITM)     │     │  (instant deny) │
└─────────────┘     └──────────────┘     └─────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   LLM Judge      │
                    │  (Bankr gateway) │
                    │  OpenAI/Anthropic│
                    │  Ollama/Local    │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  SQLite/Postgres  │
                    │  (audit log)      │
                    └──────────────────┘
```

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

## License

MIT License. Built with teeth. 🌑
