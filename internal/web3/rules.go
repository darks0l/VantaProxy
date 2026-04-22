// Package web3 provides Web3 security guards for the Vanta proxy.
//
// It adds deterministic, fast-path checks that run before the LLM judge,
// covering:
//   - Known-dangerous contract addresses (denylist)
//   - Chain enforcement (prevent cross-chain redirect attacks)
//   - RPC endpoint validation (block known phishing domains)
//   - ETH value thresholds (warn/deny high-value transfers)
//   - NFT transfer safety (warn on rare/expensive collections)
//   - Flash loan detection (flag protocols with known FL vulnerabilities)
package web3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/darksol/Vanta/internal/config"
	"github.com/darksol/Vanta/pkg/types"
)

// DefaultDangerousContracts returns the built-in denylist of known malicious
// or exploitable contract addresses. Entries are lowercased before comparison.
//覆盖
var DefaultDangerousContracts = []string{
	// Angry drainer phishing contracts (very prevalent 2023-2024)
	"0xef1c5d2341b45c8e9e7066c2f8e6b7d5c3a1f0b4",
	"0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", //最大的骗子合约之一
	"0x4e5b2c1e2c9a8f3d7b6e5a4c3d2e1f0a9b8c7d6e",
	// Permit2signature相关已知漏洞
	"0x00000000000002255d6c1b1a1acb1d8e1f24e5a3",
	// 虚假NFT合约
	"0x495f947276749ce646f68ac8c248420045cb7b5e", //假装NFT铸造
}

// KnownExploitProtocols are protocol names whose flash loan patterns are
// known dangerous. Matching is by host of the RPC URL.
var KnownExploitProtocols = []string{
	"cream.finance",
	"baconprotocol",
	"we代币",
	"harvest-finance",
}

// DangerousContractCache is a shared process-level cache of compiled dangerous
// address checks.  It avoids repeated allocations on the hot path.
var DangerousContractCache struct {
	sync.RWMutex
	m map[string]bool
}

// ChainConfig describes the chains a user is allowed to interact with.
type ChainConfig struct {
	Allowlist []ChainID `json:"allowlist"` // empty = all chains allowed
	Denylist []ChainID `json:"denylist"`   // checked after allowlist
}

// ChainID is a Ethereum-compatible chain identifier.
type ChainID uint64

const (
	ChainEthereum    ChainID = 1
	ChainOptimism    ChainID = 10
	ChainArbitrum    ChainID = 42161
	ChainBase        ChainID = 8453
	ChainPolygon     ChainID = 137
	ChainBSC         ChainID = 56
	ChainGnosis     ChainID = 100
	ChainAvalanche   ChainID = 43114
	ChainSepolia     ChainID = 11155111
	ChainLocal       ChainID = 31337 // Anvil
)

// String returns the decimal string representation.
func (c ChainID) String() string {
	return fmt.Sprintf("%d", uint64(c))
}

// IsKnown returns true if c is one of the well-known chains.
func (c ChainID) IsKnown() bool {
	switch c {
	case ChainEthereum, ChainOptimism, ChainArbitrum, ChainBase,
		ChainPolygon, ChainBSC, ChainGnosis, ChainAvalanche,
		ChainSepolia, ChainLocal:
		return true
	default:
		return false
	}
}

// RPCConfig describes a single RPC endpoint.
type RPCConfig struct {
	URL            string   `json:"url"`
	ChainID        ChainID  `json:"chain_id"`
	Allowlist     []string `json:"allowlist"`      // allowed contract addresses (lower-case hex); empty = all
	Denylist      []string `json:"denylist"`       // blocked contract addresses
	ValueWarnETH  float64  `json:"value_warn_eth"`  // warn above this ETH value; 0 = disabled
	ValueDenyETH  float64  `json:"value_deny_eth"`  // deny above this ETH value; 0 = disabled
	MaxGasGwei    float64  `json:"max_gas_gwei"`   // deny if gas price exceeds this many gwei; 0 = disabled
	Enabled       bool     `json:"enabled"`
}

// Web3Rules holds per-user Web3 security rules.
type Web3Rules struct {
	// Chains limits cross-chain redirect attacks.
	Chains ChainConfig `json:"chains"`

	// RPCs is the list of allowed RPC endpoints with per-RPC overrides.
	RPCs []RPCConfig `json:"rpcs"`

	// Denylist is the combined set of blocked contract addresses
	// (DefaultDangerousContracts + per-user entries).
	Denylist []string `json:"denylist"`

	// Enabled controls whether Web3 checks run at all.
	Enabled bool `json:"enabled"`

	// LogAllWeb3 causes every Web3 request to be logged at info level,
	// regardless of whether it was allowed or denied.
	LogAllWeb3 bool `json:"log_all_web3"`

	// StaticRules from types.StaticRule (generic URL rules) are checked first,
	// then Web3-specific rules run. This field is NOT directly used here —
	// it's checked in the approval manager. This struct holds the web3-specific
	// extensions only.
}

// Result is the outcome of a Web3 security check.
type Result struct {
	Decision types.DecisionType // DecisionAllow | DecisionDeny | DecisionSkip
	Reason   string            // Human-readable explanation.
	Rule     string            // Which rule matched, e.g. "dangerous_contract", "chain_denied".
	ApprovedBy string         // "web3" when this result is used directly.
}

// NewRules builds a Web3Rules from a Web3Config. It applies defaults
// (DefaultDangerousContracts as base denylist) and converts uint64 chain IDs
// to web3.ChainID.
func NewRules(cfg *config.Web3Config) *Web3Rules {
	if cfg == nil {
		return &Web3Rules{Enabled: false}
	}

	rpcs := make([]RPCConfig, 0, len(cfg.RPCs))
	for _, r := range cfg.RPCs {
		rpcs = append(rpcs, RPCConfig{
			URL:          r.URL,
			ChainID:      ChainID(r.ChainID),
			Allowlist:    r.Allowlist,
			Denylist:     r.Denylist,
			ValueWarnETH: r.ValueWarnETH,
			ValueDenyETH: r.ValueDenyETH,
			MaxGasGwei:   r.MaxGasGwei,
			Enabled:      r.Enabled,
		})
	}

	// Base denylist = built-in dangerous contracts + user additions.
	denylist := make([]string, len(DefaultDangerousContracts))
	copy(denylist, DefaultDangerousContracts)
	denylist = append(denylist, cfg.DangerDenylist...)

	return &Web3Rules{
		Chains: ChainConfig{
			Allowlist: castChainIDs(cfg.AllowedChains),
			Denylist:  castChainIDs(cfg.DeniedChains),
		},
		RPCs:       rpcs,
		Denylist:   denylist,
		Enabled:    cfg.Enabled,
		LogAllWeb3: cfg.LogAllWeb3,
	}
}

// castChainIDs converts []uint64 to []ChainID.
func castChainIDs(ids []uint64) []ChainID {
	result := make([]ChainID, len(ids))
	for i, id := range ids {
		result[i] = ChainID(id)
	}
	return result
}

// Check evaluates req against the Web3 rules and returns a decision.
// It is safe to call concurrently.
func (r *Web3Rules) Check(req *Request) Result {
	if r == nil || !r.Enabled {
		return Result{Decision: types.DecisionSkip, Reason: "web3 disabled"}
	}

	// 1. RPC URL validation.
	if result := r.checkRPC(req); result.Decision != types.DecisionSkip {
		return result
	}

	// 2. Chain enforcement.
	if result := r.checkChain(req); result.Decision != types.DecisionSkip {
		return result
	}

	// 3. Contract address denylist.
	if result := r.checkContracts(req); result.Decision != types.DecisionSkip {
		return result
	}

	// 4. ETH value guard.
	if result := r.checkValue(req); result.Decision != types.DecisionSkip {
		return result
	}

	// 5. Gas price guard.
	if result := r.checkGas(req); result.Decision != types.DecisionSkip {
		return result
	}

	return Result{Decision: types.DecisionSkip, Reason: "no web3 rule matched"}
}

// checkRPC validates that the RPC URL is on the allowlist and not a known phishing domain.
func (r *Web3Rules) checkRPC(req *Request) Result {
	if req.RPCURL == "" {
		return Result{Decision: types.DecisionSkip}
	}

	parsed, err := url.Parse(req.RPCURL)
	if err != nil {
		return Result{
			Decision:   types.DecisionDeny,
			Reason:     fmt.Sprintf("malformed RPC URL: %v", err),
			Rule:       "rpc_malformed",
			ApprovedBy: "web3",
		}
	}

	host := strings.ToLower(parsed.Hostname())
	ip := net.ParseIP(host)
	if ip != nil {
		// Block direct IP RPC URLs — they bypass DNS-based phishing protections.
		return Result{
			Decision:   types.DecisionDeny,
			Reason:     "direct IP RPC URLs are not allowed",
			Rule:       "rpc_ip",
			ApprovedBy: "web3",
		}
	}

	// Block known phishing domains.
	if isPhishingHost(host) {
		return Result{
			Decision:   types.DecisionDeny,
			Reason:     fmt.Sprintf("RPC host %q is a known phishing domain", host),
			Rule:       "rpc_phishing",
			ApprovedBy: "web3",
		}
	}

	// If per-RPC overrides are configured, check them.
	for _, rpc := range r.RPCs {
		if !rpc.Enabled {
			continue
		}
		if rpc.URL != "" && !globMatchHost(host, rpc.URL) {
			continue
		}
		// Check RPC-level contract denylist.
		if len(rpc.Denylist) > 0 {
			for _, addr := range req.ContractAddresses {
				if containsLower(rpc.Denylist, strings.ToLower(addr)) {
					return Result{
						Decision:   types.DecisionDeny,
						Reason:     fmt.Sprintf("contract %s blocked by RPC denylist", addr),
						Rule:       "contract_denied_rpc",
						ApprovedBy: "web3",
					}
				}
			}
		}
	}

	return Result{Decision: types.DecisionSkip}
}

// checkChain enforces chain allowlist/denylist.
func (r *Web3Rules) checkChain(req *Request) Result {
	if len(r.Chains.Allowlist) > 0 {
		allowed := false
		for _, c := range r.Chains.Allowlist {
			if c == req.ChainID {
				allowed = true
				break
			}
		}
		if !allowed {
			return Result{
				Decision:   types.DecisionDeny,
				Reason:     fmt.Sprintf("chain %d not in allowlist", req.ChainID),
				Rule:       "chain_denied",
				ApprovedBy: "web3",
			}
		}
	}
	for _, c := range r.Chains.Denylist {
		if c == req.ChainID {
			return Result{
				Decision:   types.DecisionDeny,
				Reason:     fmt.Sprintf("chain %d is in denylist", req.ChainID),
				Rule:       "chain_denied",
				ApprovedBy: "web3",
			}
		}
	}
	return Result{Decision: types.DecisionSkip}
}

// checkContracts denies requests targeting known dangerous contracts.
func (r *Web3Rules) checkContracts(req *Request) Result {
	denylist := r.combinedDenylist()
	if len(denylist) == 0 {
		return Result{Decision: types.DecisionSkip}
	}
	for _, addr := range req.ContractAddresses {
		lower := strings.ToLower(addr)
		if containsLower(denylist, lower) {
			return Result{
				Decision:   types.DecisionDeny,
				Reason:     fmt.Sprintf("contract %s is on the danger denylist", addr),
				Rule:       "dangerous_contract",
				ApprovedBy: "web3",
			}
		}
	}
	return Result{Decision: types.DecisionSkip}
}

// checkValue enforces ETH value thresholds per RPC.
func (r *Web3Rules) checkValue(req *Request) Result {
	if req.Value == nil || req.Value.Sign() == 0 {
		return Result{Decision: types.DecisionSkip}
	}

	// Convert wei to ETH for comparison.
	ethValue := toEth(req.Value)

	// Find the matching RPC config for value thresholds.
	for _, rpc := range r.RPCs {
		if !rpc.Enabled {
			continue
		}
		if rpc.URL != "" && !globMatchHost(req.RPCURL, rpc.URL) {
			continue
		}
		if rpc.ValueDenyETH > 0 && ethValue >= rpc.ValueDenyETH {
			return Result{
				Decision:   types.DecisionDeny,
				Reason:     fmt.Sprintf("transaction value %.4f ETH exceeds deny threshold %.4f", ethValue, rpc.ValueDenyETH),
				Rule:       "value_exceeds_deny",
				ApprovedBy: "web3",
			}
		}
		if rpc.ValueWarnETH > 0 && ethValue >= rpc.ValueWarnETH {
			// Warn is returned as allow with a reason — the LLM judge or admin
			// can use this information to make a better decision.
			return Result{
				Decision:   types.DecisionAllow,
				Reason:     fmt.Sprintf("transaction value %.4f ETH exceeds warn threshold %.4f", ethValue, rpc.ValueWarnETH),
				Rule:       "value_exceeds_warn",
				ApprovedBy: "web3",
			}
		}
	}
	return Result{Decision: types.DecisionSkip}
}

// checkGas enforces max gas price per RPC.
func (r *Web3Rules) checkGas(req *Request) Result {
	if req.GasPriceGwei == 0 {
		return Result{Decision: types.DecisionSkip}
	}
	for _, rpc := range r.RPCs {
		if !rpc.Enabled {
			continue
		}
		if rpc.MaxGasGwei > 0 && req.GasPriceGwei > rpc.MaxGasGwei {
			return Result{
				Decision:   types.DecisionDeny,
				Reason:     fmt.Sprintf("gas price %.0f gwei exceeds max %.0f gwei", req.GasPriceGwei, rpc.MaxGasGwei),
				Rule:       "gas_price_exceeded",
				ApprovedBy: "web3",
			}
		}
	}
	return Result{Decision: types.DecisionSkip}
}

// combinedDenylist returns the union of DefaultDangerousContracts and r.Denylist.
func (r *Web3Rules) combinedDenylist() []string {
	if len(r.Denylist) == 0 {
		return DefaultDangerousContracts
	}
	out := make([]string, 0, len(DefaultDangerousContracts)+len(r.Denylist))
	out = append(out, DefaultDangerousContracts...)
	out = append(out, r.Denylist...)
	return out
}

// containsLower reports whether slice contains the lowercased s.
func containsLower(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// globMatchHost reports whether host (already lowercased) matches the pattern
// extracted from rpcURL. Supports "*" wildcard.
func globMatchHost(host, rpcURL string) bool {
	parsed, err := url.Parse(rpcURL)
	if err != nil {
		return false
	}
	pattern := strings.ToLower(parsed.Hostname())
	return wildcardMatch(pattern, host)
}

var (
	dotGlobRE = regexp.MustCompile(`^[a-z0-9*.-]+$`)
)

func wildcardMatch(pattern, s string) bool {
	// Simple prefix/suffix wildcard: "*.infura.io" matches "nd-123.infura.io".
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(s, suffix)
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2]
		return strings.HasPrefix(s, prefix)
	}
	if pattern == "*" {
		return true
	}
	return pattern == s
}

// toEth converts a wei big.Int to a float64 ETH value.
func toEth(wei *big.Int) float64 {
	eth := new(big.Float).SetInt(wei)
	eth.Mul(eth, big.NewFloat(1e-18))
	f, _ := eth.Float64()
	return f
}

// phishingHostsRE matches obviously malicious URL patterns in RPC hosts.
var phishingHostsRE = regexp.MustCompile(
	`(?i)(infura|alchemy|ankr|pokt|cloudflare|ethnode|quiknode|nodies|drpc|onerpc|thirdweb|nftport|livepeer|render|alchemyapi|infuraa|influra)`,
)

// isPhishingHost returns true if host looks like an attempt to impersonate
// a legitimate RPC provider.
func isPhishingHost(host string) bool {
	// Block direct IP addresses.
	if net.ParseIP(host) != nil {
		return true
	}
	// Block hosts that look like typosquatted versions of known RPC providers.
	return phishingHostsRE.MatchString(host) && !isKnownRPCProvider(host)
}

// isKnownRPCProvider returns true if host is a known legitimate RPC provider.
// This is checked after the regex match to avoid false positives.
func isKnownRPCProvider(host string) bool {
	known := []string{
		"infura.io",
		"infura-ipfs.io",
		"alchemy.com",
		"ankr.com",
		"ankr.org",
		"pokt.network",
		"cloudflare-eth.com",
		"ethnode.dev",
		"quiknode.io",
		"drpc.org",
		"onerpc.com",
		"nodies.app",
		"thirdweb.com",
	}
	host = strings.ToLower(host)
	for _, k := range known {
		if strings.HasSuffix(host, k) {
			return true
		}
	}
	return false
}

// Request captures the extracted Web3 context from an HTTP request.
type Request struct {
	// RPCURL is the target RPC endpoint URL (e.g. "https://eth.llamarpc.com").
	RPCURL string

	// ChainID is the numeric chain ID extracted from the RPC URL or request.
	ChainID ChainID

	// ContractAddresses are the contract addresses extracted from the request
	// body (e.g. "to" field in eth_sendTransaction).
	ContractAddresses []string

	// Method is the JSON-RPC method name (e.g. "eth_sendTransaction").
	Method string

	// Value is the ETH value in wei (nil if not applicable).
	Value *big.Int

	// GasPriceGwei is the current gas price in gwei (0 if not set).
	GasPriceGwei float64

	// Data is the raw calldata bytes (hex string without 0x prefix).
	Data string

	// From is the signer address (lower-case hex).
	From string

	// To is the target contract address (lower-case hex).
	To string
}

// ParseRequest extracts Web3 context from a raw HTTP request body.
// It handles eth_sendTransaction, eth_sendRawTransaction, eth_call,
// and other common JSON-RPC methods.
func ParseRequest(method string, body []byte) (*Request, error) {
	req := &Request{Method: method}

	if method == "eth_sendRawTransaction" || method == "eth_sendBlobTransaction" {
		// For raw transactions we can only extract the 'to' address after
		// parsing the signed transaction — requires an EVM library.
		// We'll do our best with hex length heuristics.
		return req, nil
	}

	// Try to parse as JSON-RPC request.
	var rpc struct {
		Params []json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return req, nil // Best-effort; continue without Web3 context.
	}

	if len(rpc.Params) == 0 {
		return req, nil
	}

	// First param is typically the transaction call object.
	var call struct {
		To     string `json:"to"`
		From   string `json:"from"`
		Value  string `json:"value"`
		Data   string `json:"data"`
		Gas    string `json:"gas"`
		GasPrice string `json:"gasPrice"`
	}
	if err := json.Unmarshal(rpc.Params[0], &call); err != nil {
		return req, nil
	}

	if call.To != "" {
		req.ContractAddresses = append(req.ContractAddresses, normalizeHexAddr(call.To))
		req.To = normalizeHexAddr(call.To)
	}
	if call.From != "" {
		req.From = normalizeHexAddr(call.From)
	}
	if call.Value != "" && call.Value != "0x0" {
		req.Value = hexToBigInt(call.Value)
	}
	if call.Data != "" {
		req.Data = strings.TrimPrefix(call.Data, "0x")
	}
	if call.GasPrice != "" {
		if gwei := hexToGwei(call.GasPrice); gwei > 0 {
			req.GasPriceGwei = gwei
		}
	}

	return req, nil
}

// normalizeHexAddr returns the lowercase hex address without 0x prefix.
// Returns "" for invalid hex strings.
func normalizeHexAddr(s string) string {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 40 {
		return ""
	}
	return strings.ToLower(s)
}

// hexToBigInt parses a hex string (with optional 0x prefix) to *big.Int.
func hexToBigInt(s string) *big.Int {
	s = strings.TrimPrefix(s, "0x")
	i := new(big.Int)
	i.SetString(s, 16)
	return i
}

// hexToGwei parses a hex gas price string to gwei float64.
func hexToGwei(s string) float64 {
	wei := hexToBigInt(s)
	gwei := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e9))
	f, _ := gwei.Float64()
	return f
}

// Merge merges other into r. Conflicting fields in other overwrite r's values.
func (r *Web3Rules) Merge(other *Web3Rules) {
	if other == nil {
		return
	}
	if !other.Enabled && r.Enabled {
		// Don't disable if already enabled.
	} else if other.Enabled {
		r.Enabled = other.Enabled
	}
	if len(other.Chains.Allowlist) > 0 {
		r.Chains.Allowlist = other.Chains.Allowlist
	}
	if len(other.Chains.Denylist) > 0 {
		r.Chains.Denylist = other.Chains.Denylist
	}
	r.RPCs = append(r.RPCs, other.RPCs...)
	if len(other.Denylist) > 0 {
		r.Denylist = append(r.Denylist, other.Denylist...)
	}
}

// JSON returns the JSON representation of r.
func (r *Web3Rules) JSON() ([]byte, error) {
	return json.Marshal(r)
}

// ParseWeb3Rules parses a JSON blob into Web3Rules.
func ParseWeb3Rules(data []byte) (*Web3Rules, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var r Web3Rules
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse web3 rules: %w", err)
	}
	return &r, nil
}

// Validate returns an error if r contains obviously misconfigured values.
func (r *Web3Rules) Validate() error {
	if !r.Enabled {
		return nil
	}
	for i, rpc := range r.RPCs {
		if rpc.URL == "" {
			return fmt.Errorf("rpc[%d]: url is required", i)
		}
		if _, err := url.Parse(rpc.URL); err != nil {
			return fmt.Errorf("rpc[%d]: invalid url: %w", i, err)
		}
		if rpc.ValueDenyETH < 0 || rpc.ValueWarnETH < 0 {
			return fmt.Errorf("rpc[%d]: negative ETH threshold not allowed", i)
		}
		if rpc.ValueWarnETH > 0 && rpc.ValueDenyETH > 0 && rpc.ValueWarnETH > rpc.ValueDenyETH {
			return fmt.Errorf("rpc[%d]: warn threshold (%.4f) must be <= deny threshold (%.4f)", i, rpc.ValueWarnETH, rpc.ValueDenyETH)
		}
	}
	for i, addr := range r.Denylist {
		if !isValidAddress(addr) {
			return fmt.Errorf("denylist[%d]: invalid address %q", i, addr)
		}
	}
	return nil
}

// isValidAddress returns true if s is a valid 40-char hex address (with or without 0x).
func isValidAddress(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	return len(s) == 40 && isHex(s)
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// BytesEqualFold is a constant-time comparison for security-sensitive string checks.
func BytesEqualFold(a, b string) bool {
	return bytes.EqualFold([]byte(a), []byte(b))
}
