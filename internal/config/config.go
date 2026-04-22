package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/darksol/Vanta/internal/envutil"
	"gopkg.in/yaml.v3"
)

// DatabaseConfig contains PostgreSQL connection settings.
type DatabaseConfig struct {
	URL      string `yaml:"url"`       // e.g. "${DATABASE_URL}"
	MaxConns int32  `yaml:"max_conns"` // default 10
	MinConns int32  `yaml:"min_conns"` // default 2
}

// AdminConfig contains settings for the admin web UI and API.
type AdminConfig struct {
	SecureCookie bool `yaml:"secure_cookie"` // set Secure flag on auth cookies (enable behind TLS proxy)
}

// Config represents the gateway configuration
// Web3RPCConfig describes a single allowed RPC endpoint.
type Web3RPCConfig struct {
	URL            string    `yaml:"url"`                // e.g. "https://eth.llamarpc.com"
	ChainID        uint64   `yaml:"chain_id"`          // numeric chain ID (1=mainnet, 8453=base, etc.)
	ChainName      string   `yaml:"chain_name"`        // human-readable name (optional)
	Allowlist      []string `yaml:"allowlist"`         // allowed contract addresses (lower-case hex); empty=all
	Denylist       []string `yaml:"denylist"`          // blocked contract addresses
	ValueWarnETH  float64  `yaml:"value_warn_eth"`  // warn above this ETH value; 0=disabled
	ValueDenyETH   float64  `yaml:"value_deny_eth"`  // deny above this ETH value; 0=disabled
	MaxGasGwei     float64  `yaml:"max_gas_gwei"`     // deny if gas price exceeds this many gwei; 0=disabled
	Enabled        bool     `yaml:"enabled"`           // default true
}

// Web3Config contains Web3 security settings.
type Web3Config struct {
	Enabled         bool               `yaml:"enabled"`           // enable Web3 security checks
	LogAllWeb3      bool               `yaml:"log_all_web3"`     // log every Web3 request at info level
	RPCs            []Web3RPCConfig    `yaml:"rpcs"`             // allowed RPC endpoints
	AllowedChains   []uint64           `yaml:"allowed_chains"`   // chain IDs allowed for this user; empty=all
	DeniedChains    []uint64           `yaml:"denied_chains"`    // chain IDs denied for this user
	DangerDenylist  []string           `yaml:"danger_denylist"`  // additional blocked contract addresses
}

type Config struct {
	LogLevel    string            `yaml:"log_level"` // "debug", "info" (default), "warn", "error"
	Proxy       ProxyConfig       `yaml:"proxy"`
	TLS         TLSConfig         `yaml:"tls"`
	Approval    ApprovalConfig    `yaml:"approval"`
	Audit       AuditConfig       `yaml:"audit"`
	Database    DatabaseConfig    `yaml:"database"`
	LLMJudge    LLMJudgeConfig    `yaml:"llm_judge"`
	Admin       AdminConfig       `yaml:"admin"`
	Web3        Web3Config        `yaml:"web3"`
}

// ProxyConfig contains proxy server settings
type ProxyConfig struct {
	Port                       int           `yaml:"port"`
	ReadTimeout                time.Duration `yaml:"read_timeout"`
	WriteTimeout               time.Duration `yaml:"write_timeout"`
	IdleTimeout                time.Duration `yaml:"idle_timeout"`
	AllowedPrivateCIDRs        []string      `yaml:"allowed_private_cidrs"`         // CIDRs exempted from SSRF blocklist (e.g. ["10.0.0.0/8"])
	InsecureSkipUpstreamVerify bool          `yaml:"insecure_skip_upstream_verify"` // default false; set true to skip TLS verification on upstream connections
	InsecureSkipVerifyHosts    []string      `yaml:"insecure_skip_verify_hosts"`    // per-host TLS skip: when non-empty, only these hostnames skip verification
	RateLimitPerIP             *int          `yaml:"rate_limit_per_ip"`             // requests/sec per source IP (default 50; explicit 0 disables)
	RateLimitBurst             int           `yaml:"rate_limit_burst"`              // token bucket burst size per IP; default 100 when rate limiting is enabled
}

// TLSConfig contains TLS/certificate settings
type TLSConfig struct {
	CACertPath       string `yaml:"ca_cert_path"`
	CAKeyPath        string `yaml:"ca_key_path"`
	MaxCertCacheSize int    `yaml:"max_cert_cache_size"` // 0 = use default (10000)
}

// ApprovalConfig contains approval flow settings
type ApprovalConfig struct {
	Mode         string        `yaml:"mode"` // "llm" | "passthrough" (default: "llm")
	Timeout      time.Duration `yaml:"timeout"`
}

// LLMJudgeConfig contains settings for the LLM-as-judge approval path.
// When enabled, LLM components (judge, adapters, policy agent) are initialised
// for both live approval (requires approval.mode "llm") and offline admin
// features (evals, policy authoring) which work regardless of approval mode.
// AWS credentials are read from the standard chain: env vars, ~/.aws/credentials, IAM roles.
// For direct Anthropic or OpenAI providers, set the corresponding API key field or env var.
type LLMJudgeConfig struct {
	Enabled                 bool          `yaml:"enabled"`
	Provider                string        `yaml:"provider"`                  // "bedrock-anthropic" | "anthropic" | "openai" | "bankr"
	BedrockAWSRegion        string        `yaml:"bedrock_aws_region"`        // overrides AWS_REGION env var (bedrock-anthropic only)
	AWSRegion               string        `yaml:"aws_region"`                // deprecated: use bedrock_aws_region
	Timeout                 time.Duration `yaml:"timeout"`
	FallbackMode            string        `yaml:"fallback_mode"`            // "deny" | "passthrough"
	EvalModel               string        `yaml:"eval_model"`
	FastModel               string        `yaml:"fast_model"`
	ThinkingModel           string        `yaml:"thinking_model"`
	MaxConcurrency          int           `yaml:"max_concurrency"`           // max parallel API calls (default 100)
	CircuitBreakerThreshold int           `yaml:"circuit_breaker_threshold"` // consecutive failures to trip (default 5)
	CircuitBreakerCooldown  time.Duration `yaml:"circuit_breaker_cooldown"`  // cooldown before half-open probe (default 10s)
	AnthropicAPIKey         string        `yaml:"anthropic_api_key"`         // API key for direct Anthropic provider (or env ANTHROPIC_API_KEY)
	AnthropicBaseURL        string        `yaml:"anthropic_base_url"`        // override Anthropic API base URL (e.g. for proxies)
	OpenAIAPIKey            string        `yaml:"openai_api_key"`            // API key for OpenAI provider (or env OPENAI_API_KEY)
	OpenAIBaseURL           string        `yaml:"openai_base_url"`           // override OpenAI API base URL (e.g. for proxies)
	// Bankr-specific config
	BankrURL                string        `yaml:"bankr_url"`                 // Bankr gateway URL (default: http://localhost:18789)
	BankrAPIKey            string        `yaml:"bankr_api_key"`             // Bankr API key (or env BANKR_API_KEY)
}

// AuditConfig contains audit logging settings
type AuditConfig struct {
	Output string `yaml:"output"`
	Format string `yaml:"format"`
}

// Load reads and parses the configuration file. If the file does not exist,
// it falls back to passthrough defaults so the gateway can start without a
// config file (e.g. Docker quickstart).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Warn("config file not found, using defaults (passthrough mode)", "path", path)
			cfg := &Config{
				Approval: ApprovalConfig{Mode: "passthrough"},
			}
			cfg.LLMJudge.Enabled = false
			cfg.Database.URL = "${DATABASE_URL}"
			cfg.expandEnvVars()
			cfg.applyDefaults()
			if err := cfg.validate(); err != nil {
				return nil, fmt.Errorf("invalid default configuration: %w", err)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Expand environment variables
	config.expandEnvVars()

	// Apply defaults
	config.applyDefaults()

	// Validate
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// expandEnvVars expands explicit env references (e.g. ${VAR}, $VAR) only for
// secret fields.
func (c *Config) expandEnvVars() {
	// Expand database URL
	c.Database.URL = envutil.Expand(c.Database.URL)
	// Expand LLM API keys
	c.LLMJudge.AnthropicAPIKey = envutil.Expand(c.LLMJudge.AnthropicAPIKey)
	c.LLMJudge.OpenAIAPIKey = envutil.Expand(c.LLMJudge.OpenAIAPIKey)
}

// applyDefaults sets default values for unspecified config fields
func (c *Config) applyDefaults() {
	if c.Proxy.Port == 0 {
		c.Proxy.Port = 8080
	}
	if c.Proxy.ReadTimeout == 0 {
		c.Proxy.ReadTimeout = 600 * time.Second
	}
	if c.Proxy.WriteTimeout == 0 {
		c.Proxy.WriteTimeout = 600 * time.Second
	}
	if c.Proxy.IdleTimeout == 0 {
		c.Proxy.IdleTimeout = 120 * time.Second
	}
	if c.TLS.CACertPath == "" {
		c.TLS.CACertPath = "./certs/ca.crt"
	}
	if c.TLS.CAKeyPath == "" {
		c.TLS.CAKeyPath = "./certs/ca.key"
	}
	if c.Approval.Mode == "" {
		c.Approval.Mode = "llm"
		// When mode defaults to "llm", also default llm_judge.enabled to true
		// so the config is valid out of the box. Users who explicitly set
		// approval.mode: llm with llm_judge.enabled: false will be caught by validation.
		if !c.LLMJudge.Enabled {
			c.LLMJudge.Enabled = true
		}
	}
	if c.Approval.Timeout == 0 {
		c.Approval.Timeout = 30 * time.Second
	}
	if c.LLMJudge.Provider == "" {
		c.LLMJudge.Provider = "bankr"
	}
	if c.LLMJudge.BedrockAWSRegion == "" && c.LLMJudge.AWSRegion != "" {
		c.LLMJudge.BedrockAWSRegion = c.LLMJudge.AWSRegion
	}
	if c.LLMJudge.AnthropicAPIKey == "" {
		c.LLMJudge.AnthropicAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if c.LLMJudge.OpenAIAPIKey == "" {
		c.LLMJudge.OpenAIAPIKey = os.Getenv("OPENAI_API_KEY")
	}
	if c.LLMJudge.BankrURL == "" {
		c.LLMJudge.BankrURL = os.Getenv("BANKR_URL")
		if c.LLMJudge.BankrURL == "" {
			c.LLMJudge.BankrURL = "http://localhost:18789"
		}
	}
	if c.LLMJudge.BankrAPIKey == "" {
		c.LLMJudge.BankrAPIKey = os.Getenv("BANKR_API_KEY")
	}
	if c.LLMJudge.EvalModel == "" {
		c.LLMJudge.EvalModel = "anthropic/claude-opus-4-6"
	}
	if c.LLMJudge.FastModel == "" {
		c.LLMJudge.FastModel = "anthropic/claude-haiku-4-6"
	}
	if c.LLMJudge.ThinkingModel == "" {
		c.LLMJudge.ThinkingModel = c.LLMJudge.EvalModel
	}
	if c.LLMJudge.Timeout == 0 {
		c.LLMJudge.Timeout = 30 * time.Second
	}
	if c.LLMJudge.FallbackMode == "" {
		c.LLMJudge.FallbackMode = "deny"
	}
	if c.LLMJudge.MaxConcurrency == 0 {
		c.LLMJudge.MaxConcurrency = 100
	}
	if c.LLMJudge.CircuitBreakerThreshold == 0 {
		c.LLMJudge.CircuitBreakerThreshold = 5
	}
	if c.LLMJudge.CircuitBreakerCooldown == 0 {
		c.LLMJudge.CircuitBreakerCooldown = 10 * time.Second
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Audit.Output == "" {
		c.Audit.Output = "stderr"
	}
	if c.Audit.Format == "" {
		c.Audit.Format = "json"
	}
	if c.Database.MaxConns == 0 {
		c.Database.MaxConns = 10
	}
	if c.Database.MinConns == 0 {
		c.Database.MinConns = 2
	}
	if c.Proxy.RateLimitPerIP == nil {
		defaultRate := 50
		c.Proxy.RateLimitPerIP = &defaultRate
	}
	if *c.Proxy.RateLimitPerIP > 0 && c.Proxy.RateLimitBurst == 0 {
		c.Proxy.RateLimitBurst = 100
	}
	// Web3 defaults.
	if c.Web3.RPCs == nil {
		c.Web3.RPCs = []Web3RPCConfig{}
	}
	for i := range c.Web3.RPCs {
		if c.Web3.RPCs[i].Enabled {
			continue
		}
		c.Web3.RPCs[i].Enabled = true
	}
}

// validate checks if the configuration is valid
func (c *Config) validate() error {
	if c.Proxy.Port < 1 || c.Proxy.Port > 65535 {
		return fmt.Errorf("invalid proxy port: %d", c.Proxy.Port)
	}
	if c.TLS.CACertPath == "" {
		return fmt.Errorf("ca_cert_path is required")
	}
	if c.TLS.CAKeyPath == "" {
		return fmt.Errorf("ca_key_path is required")
	}
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be one of: debug, info, warn, error (got %q)", c.LogLevel)
	}

	if c.Audit.Format != "json" {
		return fmt.Errorf("only json audit format is supported")
	}
	switch c.Approval.Mode {
	case "llm", "passthrough":
	default:
		return fmt.Errorf("approval.mode must be one of: llm, passthrough")
	}

	if c.Approval.Mode == "llm" && !c.LLMJudge.Enabled {
		return fmt.Errorf("approval.mode is 'llm' but llm_judge.enabled is false")
	}

	switch c.LLMJudge.FallbackMode {
	case "", "deny", "passthrough":
		// empty is valid (applyDefaults fills it to "deny")
	default:
		return fmt.Errorf("llm_judge.fallback_mode must be one of: deny, passthrough (got %q)", c.LLMJudge.FallbackMode)
	}

	if c.LLMJudge.Enabled {
		switch c.LLMJudge.Provider {
		case "bedrock-anthropic", "":
			// AWS credentials are handled via the standard chain (env, IAM, etc.)
		case "anthropic":
			if c.LLMJudge.AnthropicAPIKey == "" {
				return fmt.Errorf("llm_judge.anthropic_api_key is required when provider is 'anthropic' (or set the environment variable ANTHROPIC_API_KEY)")
			}
		case "openai":
			if c.LLMJudge.OpenAIAPIKey == "" {
				return fmt.Errorf("llm_judge.openai_api_key is required when provider is 'openai' (or set the environment variable OPENAI_API_KEY)")
			}
		case "bankr":
			if c.LLMJudge.BankrAPIKey == "" {
				return fmt.Errorf("llm_judge.bankr_api_key is required when provider is 'bankr' (or set the environment variable BANKR_API_KEY)")
			}
		default:
			return fmt.Errorf("llm_judge.provider must be one of: bedrock-anthropic, anthropic, openai, bankr (got %q)", c.LLMJudge.Provider)
		}
	}

	for _, cidr := range c.Proxy.AllowedPrivateCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid allowed_private_cidrs entry %q: %w", cidr, err)
		}
	}

	for _, host := range c.Proxy.InsecureSkipVerifyHosts {
		if host == "" {
			return fmt.Errorf("insecure_skip_verify_hosts contains an empty entry")
		}
	}

	if c.Proxy.RateLimitPerIP != nil && *c.Proxy.RateLimitPerIP < 0 {
		return fmt.Errorf("rate_limit_per_ip must be non-negative (got %d)", *c.Proxy.RateLimitPerIP)
	}
	if c.Proxy.RateLimitBurst < 0 {
		return fmt.Errorf("rate_limit_burst must be non-negative (got %d)", c.Proxy.RateLimitBurst)
	}

	// Web3 validation.
	for i, rpc := range c.Web3.RPCs {
		if !c.Web3.Enabled && i == 0 {
			break
		}
		if rpc.URL == "" {
			return fmt.Errorf("web3.rpcs[%d].url is required", i)
		}
		if rpc.ValueDenyETH < 0 || rpc.ValueWarnETH < 0 {
			return fmt.Errorf("web3.rpcs[%d]: negative ETH threshold not allowed", i)
		}
		if rpc.ValueWarnETH > 0 && rpc.ValueDenyETH > 0 && rpc.ValueWarnETH > rpc.ValueDenyETH {
			return fmt.Errorf("web3.rpcs[%d]: warn threshold (%.4f) must be <= deny threshold (%.4f)", i, rpc.ValueWarnETH, rpc.ValueDenyETH)
		}
		if rpc.MaxGasGwei < 0 {
			return fmt.Errorf("web3.rpcs[%d].max_gas_gwei must be non-negative", i)
		}
	}

	return nil
}

// Default returns a configuration with default values.
func Default() *Config {
	config := &Config{}
	config.applyDefaults()
	return config
}
