package web3

import (
	"math/big"
	"testing"
)

func TestToEth(t *testing.T) {
	tests := []struct {
		wei    string
		wantEth float64
	}{
		{"0x0", 0},
		{"0x1", 1e-18},
		{"0xde0b6b3a7640000", 1},      // 1 ETH in hex
		{"de0b6b3a7640000", 1},
		{"0x56bc75e2d63100000", 100},   // 100 ETH
		{"0x4563918244f40000", 0.1},    // 0.1 ETH
	}
	for _, tt := range tests {
		wei := hexToBigInt(tt.wei)
		got := toEth(wei)
		if got != tt.wantEth {
			t.Errorf("toEth(%s) = %f; want %f", tt.wei, got, tt.wantEth)
		}
	}
}

func TestIsValidAddress(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", true},
		{"d8da6bf26964af9d7eed9e03e53415d87aa480bb", true},
		{"0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", true},
		{"0xd8da6bf26964af9d7eed9e03e53415d87aa480b", false},  // 39 chars
		{"0xd8da6bf26964af9d7eed9e03e53415d87aa480bgg", false}, // bad chars
		{"", false},
		{"0x", false},
	}
	for _, tt := range tests {
		got := isValidAddress(tt.addr)
		if got != tt.want {
			t.Errorf("isValidAddress(%q) = %v; want %v", tt.addr, got, tt.want)
		}
	}
}

func TestGlobMatchHost(t *testing.T) {
	tests := []struct {
		host, pattern string
		want         bool
	}{
		{"nd-123.infura.io", "*.infura.io", true},
		{"alchemy.com", "*.alchemy.com", false},
		{"eth-mainnet.g.alchemy.com", "*.alchemy.com", true},
		{"quiknode.io", "quiknode.io", true},
		{"evil.quiknode.io", "quiknode.io", false},
		{"localhost", "*", true},
		{"my-rpc.example.com", "*", true},
		{"nd-123.infura.io", "nd-123.infura.io", true},
	}
	for _, tt := range tests {
		got := globMatchHost(tt.host, tt.pattern)
		if got != tt.want {
			t.Errorf("globMatchHost(%q, %q) = %v; want %v", tt.host, tt.pattern, got, tt.want)
		}
	}
}

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*.infura.io", "nd-123.infura.io", true},
		{"*.alchemy.com", "eth-mainnet.g.alchemy.com", true},
		{"*.alchemy.com", "alchemy.com", false},
		{"https://*.example.com", "https://api.example.com", false}, // no scheme stripping
		{"*", "anything", true},
		{"api.*", "api.mainnet", false}, // suffix wildcard not implemented
		{"*.pokt.network", "gateway.pokt.network", true},
		{"*.drpc.org", "eth.drpc.org", true},
	}
	for _, tt := range tests {
		got := wildcardMatch(tt.pattern, tt.s)
		if got != tt.want {
			t.Errorf("wildcardMatch(%q, %q) = %v; want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

func TestChainID_IsKnown(t *testing.T) {
	known := []ChainID{1, 10, 42161, 8453, 137, 56, 100, 43114, 11155111, 31337}
	for _, c := range known {
		if !c.IsKnown() {
			t.Errorf("ChainID(%d).IsKnown() = false; want true", c)
		}
	}
	if ChainID(99999).IsKnown() {
		t.Errorf("ChainID(99999).IsKnown() = true; want false")
	}
}

func TestStripDefaultPort(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com:443/path", "https://example.com/path"},
		{"https://example.com/path?query=1", "https://example.com/path?query=1"},
		{"http://example.com:80/path", "http://example.com/path"},
		{"https://example.com:8443/path", "https://example.com:8443/path"},
		{"http://localhost:8080/path", "http://localhost:8080/path"},
	}
	for _, tt := range tests {
		got := stripDefaultPort(tt.url)
		if got != tt.want {
			t.Errorf("stripDefaultPort(%q) = %q; want %q", tt.url, got, tt.want)
		}
	}
}

func TestParseRequest_ETHCall(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xd8da6bf26964af9d7eed9e03e53415d87aa480bb","data":"0xa9059cbb00000000000000000000000000000000000000000000000000000000"},"latest"],"id":1}`)

	req, err := ParseRequest("eth_call", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Method != "eth_call" {
		t.Errorf("Method = %q; want eth_call", req.Method)
	}
	if len(req.ContractAddresses) != 1 {
		t.Fatalf("ContractAddresses = %v; want 1 entry", req.ContractAddresses)
	}
	if req.To != "d8da6bf26964af9d7eed9e03e53415d87aa480bb" {
		t.Errorf("To = %q; want d8da6bf26964af9d7eed9e03e53415d87aa480bb", req.To)
	}
}

func TestParseRequest_ETHValue(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"to":"0xd8da6bf26964af9d7eed9e03e53415d87aa480bb","value":"0xde0b6b3a7640000"}],"id":1}`)

	req, err := ParseRequest("eth_sendTransaction", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Value == nil {
		t.Fatal("Value = nil; want 1 ETH")
	}
	eth := toEth(req.Value)
	if eth != 1.0 {
		t.Errorf("Value ETH = %f; want 1.0", eth)
	}
}

func TestParseRequest_NoParams(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)
	req, err := ParseRequest("eth_blockNumber", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "eth_blockNumber" {
		t.Errorf("Method = %q; want eth_blockNumber", req.Method)
	}
	if len(req.ContractAddresses) != 0 {
		t.Errorf("ContractAddresses = %v; want empty", req.ContractAddresses)
	}
}

func TestParseRequest_InvalidJSON(t *testing.T) {
	body := []byte(`not json at all`)
	req, err := ParseRequest("eth_call", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return nil error (best-effort) and empty request.
	if req.Method != "eth_call" {
		t.Errorf("Method = %q; want eth_call", req.Method)
	}
}

func TestWeb3Rules_CheckNil(t *testing.T) {
	var r *Web3Rules
	result := r.Check(&Request{})
	if result.Decision != types.DecisionSkip {
		t.Errorf("nil rules: Decision = %v; want DecisionSkip", result.Decision)
	}
}

func TestWeb3Rules_CheckDisabled(t *testing.T) {
	r := &Web3Rules{Enabled: false}
	result := r.Check(&Request{})
	if result.Decision != types.DecisionSkip {
		t.Errorf("disabled rules: Decision = %v; want DecisionSkip", result.Decision)
	}
}

func TestWeb3Rules_DangerousContract(t *testing.T) {
	r := &Web3Rules{
		Enabled:   true,
		Denylist:  []string{"d8da6bf26964af9d7eed9e03e53415d87aa480bb"},
		RPCs:      []RPCConfig{{URL: "https://eth.llamarpc.com", Enabled: true}},
	}
	req := &Request{
		RPCURL:             "https://eth.llamarpc.com",
		ContractAddresses:  []string{"0xd8dA6bF26964aF9D7eEd9E03E53415D87AA480Bb"},
	}

	result := r.Check(req)
	if result.Decision != types.DecisionDeny {
		t.Errorf("dangerous contract: Decision = %v; want Deny", result.Decision)
	}
	if result.Rule != "dangerous_contract" {
		t.Errorf("Rule = %q; want dangerous_contract", result.Rule)
	}
}

func TestWeb3Rules_DangerousContractBuiltIn(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		// Not setting Denylist — uses DefaultDangerousContracts.
		RPCs: []RPCConfig{{URL: "https://eth.llamarpc.com", Enabled: true}},
	}
	// "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb" is in DefaultDangerousContracts.
	req := &Request{
		RPCURL:            "https://eth.llamarpc.com",
		ContractAddresses: []string{"0xd8da6bf26964af9d7eed9e03e53415d87aa480bb"},
	}

	result := r.Check(req)
	if result.Decision != types.DecisionDeny {
		t.Errorf("built-in dangerous contract: Decision = %v; want Deny", result.Decision)
	}
}

func TestWeb3Rules_RPCPhishing(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		RPCs:    []RPCConfig{{URL: "https://eth.llamarpc.com", Enabled: true}},
	}

	// Direct IP is blocked.
	req := &Request{RPCURL: "https://1.2.3.4/abc"}
	result := r.Check(req)
	if result.Decision != types.DecisionDeny {
		t.Errorf("direct IP RPC: Decision = %v; want Deny", result.Decision)
	}
	if result.Rule != "rpc_ip" {
		t.Errorf("Rule = %q; want rpc_ip", result.Rule)
	}
}

func TestWeb3Rules_RPCNotOnList(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		RPCs:    []RPCConfig{{URL: "https://known-rpc.example.com", Enabled: true}},
	}

	req := &Request{RPCURL: "https://unknown-rpc.example.com"}
	result := r.Check(req)
	// Unknown RPC URL is allowed (no denylist for it).
	if result.Decision == types.DecisionDeny {
		t.Errorf("unknown RPC: Decision = %v; want Skip or Allow, not Deny", result.Decision)
	}
}

func TestWeb3Rules_ValueDeny(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		RPCs: []RPCConfig{{
			URL:         "https://eth.llamarpc.com",
			Enabled:     true,
			ValueDenyETH: 0.5,
		}},
	}
	// 1 ETH > 0.5 ETH deny threshold.
	wei := new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1))
	req := &Request{
		RPCURL: "https://eth.llamarpc.com",
		Value:  wei,
	}

	result := r.Check(req)
	if result.Decision != types.DecisionDeny {
		t.Errorf("value deny: Decision = %v; want Deny", result.Decision)
	}
	if result.Rule != "value_exceeds_deny" {
		t.Errorf("Rule = %q; want value_exceeds_deny", result.Rule)
	}
}

func TestWeb3Rules_ValueWarn(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		RPCs: []RPCConfig{{
			URL:          "https://eth.llamarpc.com",
			Enabled:      true,
			ValueWarnETH:  0.05,
			ValueDenyETH:  0, // no deny
		}},
	}
	// 0.1 ETH > 0.05 ETH warn threshold.
	wei := new(big.Int).Mul(big.NewInt(1e17), big.NewInt(1))
	req := &Request{
		RPCURL: "https://eth.llamarpc.com",
		Value:  wei,
	}

	result := r.Check(req)
	if result.Decision != types.DecisionAllow {
		t.Errorf("value warn: Decision = %v; want Allow", result.Decision)
	}
	if result.Rule != "value_exceeds_warn" {
		t.Errorf("Rule = %q; want value_exceeds_warn", result.Rule)
	}
}

func TestWeb3Rules_GasPriceDeny(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		RPCs: []RPCConfig{{
			URL:        "https://eth.llamarpc.com",
			Enabled:    true,
			MaxGasGwei: 100,
		}},
	}
	req := &Request{
		RPCURL:       "https://eth.llamarpc.com",
		GasPriceGwei:  250,
	}

	result := r.Check(req)
	if result.Decision != types.DecisionDeny {
		t.Errorf("gas price deny: Decision = %v; want Deny", result.Decision)
	}
	if result.Rule != "gas_price_exceeded" {
		t.Errorf("Rule = %q; want gas_price_exceeded", result.Rule)
	}
}

func TestWeb3Rules_ChainAllowlist(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		Chains: ChainConfig{
			Allowlist: []ChainID{ChainBase, ChainArbitrum},
		},
	}

	// Chain 1 (Ethereum) not in allowlist.
	req := &Request{ChainID: ChainEthereum}
	result := r.Check(req)
	if result.Decision != types.DecisionDeny {
		t.Errorf("chain deny: Decision = %v; want Deny", result.Decision)
	}

	// Chain 8453 (Base) is in allowlist.
	req2 := &Request{ChainID: ChainBase}
	result2 := r.Check(req2)
	if result2.Decision == types.DecisionDeny {
		t.Errorf("chain allow: Decision = %v; want not Deny", result2.Decision)
	}
}

func TestWeb3Rules_ChainDenylist(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		Chains: ChainConfig{
			Denylist: []ChainID{ChainPolygon},
		},
	}

	req := &Request{ChainID: ChainPolygon}
	result := r.Check(req)
	if result.Decision != types.DecisionDeny {
		t.Errorf("chain denylist: Decision = %v; want Deny", result.Decision)
	}

	// Ethereum not in denylist.
	req2 := &Request{ChainID: ChainEthereum}
	result2 := r.Check(req2)
	if result2.Decision == types.DecisionDeny {
		t.Errorf("chain not denied: Decision = %v; want not Deny", result2.Decision)
	}
}

func TestWeb3Rules_NoWeb3Fields(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		RPCs:   []RPCConfig{{URL: "https://eth.llamarpc.com", Enabled: true}},
	}

	// Request with no Web3-specific fields — should skip all checks.
	req := &Request{
		RPCURL: "https://eth.llamarpc.com",
		Method: "eth_call",
	}

	result := r.Check(req)
	if result.Decision != types.DecisionSkip {
		t.Errorf("no web3 fields: Decision = %v; want Skip", result.Decision)
	}
}

func TestWeb3Rules_MultipleRulesPriority(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		Denylist: []string{"0xd8da6bf26964af9d7eed9e03e53415d87aa480bb"},
		RPCs: []RPCConfig{{
			URL:          "https://eth.llamarpc.com",
			Enabled:      true,
			ValueWarnETH: 0.01,
		}},
	}
	// Both dangerous contract AND value warn could fire.
	wei := new(big.Int).Mul(big.NewInt(1e17), big.NewInt(1)) // 0.1 ETH
	req := &Request{
		RPCURL:            "https://eth.llamarpc.com",
		ContractAddresses: []string{"0xd8da6bf26964af9d7eed9e03e53415d87aa480bb"},
		Value:             wei,
	}

	result := r.Check(req)
	if result.Decision != types.DecisionDeny {
		t.Errorf("multi-rule: Decision = %v; want Deny (dangerous contract)", result.Decision)
	}
}

func TestWeb3Rules_RPCSpecificDenylist(t *testing.T) {
	r := &Web3Rules{
		Enabled: true,
		RPCs: []RPCConfig{
			{
				URL:      "https://known-rpc.example.com",
				Enabled:  true,
				Denylist: []string{"0xd8da6bf26964af9d7eed9e03e53415d87aa480bb"},
			},
			{
				URL:     "https://other-rpc.example.com",
				Enabled: true,
				// No denylist for this RPC.
			},
		},
	}

	// Same contract blocked on known-rpc but not on other-rpc.
	addr := "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb"
	req1 := &Request{
		RPCURL:            "https://known-rpc.example.com",
		ContractAddresses: []string{addr},
	}
	req2 := &Request{
		RPCURL:            "https://other-rpc.example.com",
		ContractAddresses: []string{addr},
	}

	result1 := r.Check(req1)
	result2 := r.Check(req2)

	if result1.Decision != types.DecisionDeny {
		t.Errorf("known-rpc: Decision = %v; want Deny", result1.Decision)
	}
	if result2.Decision == types.DecisionDeny {
		t.Errorf("other-rpc: Decision = %v; want not Deny", result2.Decision)
	}
}

func TestNormalizeHexAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0xABCDEF1234567890abcdef1234567890abcdef12", "abcdef1234567890abcdef1234567890abcdef12"},
		{"abcdef1234567890abcdef1234567890abcdef12", "abcdef1234567890abcdef1234567890abcdef12"},
		{"0XABCDEF1234567890abcdef1234567890abcdef12", "abcdef1234567890abcdef1234567890abcdef12"},
		{"", ""},
		{"0x", ""},
		{"abc", ""}, // wrong length
	}
	for _, tt := range tests {
		got := normalizeHexAddr(tt.input)
		if got != tt.want {
			t.Errorf("normalizeHexAddr(%q) = %q; want %q", tt.input, got, tt.want)
		}
	}
}

func TestWeb3Rules_JSON(t *testing.T) {
	r := &Web3Rules{
		Enabled:   true,
		LogAllWeb3: true,
		RPCs: []RPCConfig{
			{URL: "https://eth.llamarpc.com", ChainID: 1, Enabled: true, ValueWarnETH: 0.1},
		},
	}

	data, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	parsed, err := ParseWeb3Rules(data)
	if err != nil {
		t.Fatalf("ParseWeb3Rules() error: %v", err)
	}
	if !parsed.Enabled {
		t.Error("parsed.Enabled = false; want true")
	}
	if len(parsed.RPCs) != 1 {
		t.Fatalf("parsed.RPCs len = %d; want 1", len(parsed.RPCs))
	}
	if parsed.RPCs[0].ValueWarnETH != 0.1 {
		t.Errorf("parsed.RPCs[0].ValueWarnETH = %f; want 0.1", parsed.RPCs[0].ValueWarnETH)
	}
}

func TestWeb3Rules_Validate(t *testing.T) {
	// Valid config.
	r := &Web3Rules{
		Enabled: true,
		RPCs: []RPCConfig{
			{URL: "https://eth.llamarpc.com", ChainID: 1, ValueDenyETH: 1.0, ValueWarnETH: 0.1},
		},
	}
	if err := r.Validate(); err != nil {
		t.Errorf("valid config: unexpected error: %v", err)
	}

	// Warn > deny is invalid.
	r2 := &Web3Rules{
		Enabled: true,
		RPCs: []RPCConfig{
			{URL: "https://eth.llamarpc.com", ValueWarnETH: 1.0, ValueDenyETH: 0.1},
		},
	}
	if err := r2.Validate(); err == nil {
		t.Error("warn > deny: expected error, got nil")
	}

	// Negative deny threshold.
	r3 := &Web3Rules{
		Enabled: true,
		RPCs: []RPCConfig{
			{URL: "https://eth.llamarpc.com", ValueDenyETH: -1.0},
		},
	}
	if err := r3.Validate(); err == nil {
		t.Error("negative deny: expected error, got nil")
	}
}

func TestParseChainID(t *testing.T) {
	tests := []struct {
		hex  string
		want uint64
		err bool
	}{
		{"0x1", 1, false},
		{"0x64", 100, false},
		{"0x2105", 8453, false},  // Base chain ID
		{"0xa", 10, false},
		{"1", 1, false},
		{"0x", 0, true},
		{"invalid", 0, true},
	}
	for _, tt := range tests {
		got, err := parseChainID(tt.hex)
		if tt.err && err == nil {
			t.Errorf("parseChainID(%q): expected error, got nil", tt.hex)
		}
		if !tt.err && err != nil {
			t.Errorf("parseChainID(%q): unexpected error: %v", tt.hex, err)
		}
		if !tt.err && got != tt.want {
			t.Errorf("parseChainID(%q) = %d; want %d", tt.hex, got, tt.want)
		}
	}
}

func TestNonceGuard_ObserveAndCheck(t *testing.T) {
	g := NewNonceGuard(100)

	// First nonce should always be valid.
	if err := g.Check(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", 0); err != nil {
		t.Errorf("first nonce: unexpected error: %v", err)
	}

	// Observe nonce 0 was broadcast.
	g.Observe(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", 0)

	// Next fresh nonce should be 1.
	if err := g.Check(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", 1); err != nil {
		t.Errorf("next nonce: unexpected error: %v", err)
	}

	// Nonce 0 should now be "already used".
	if err := g.Check(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", 0); err == nil {
		t.Error("reuse nonce: expected error, got nil")
	}

	// Nonce 5 when next is 1 should be a gap.
	if err := g.Check(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", 5); err == nil {
		t.Error("nonce gap: expected error, got nil")
	}
}

func TestNonceGuard_Advance(t *testing.T) {
	g := NewNonceGuard(100)

	g.Observe(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", 0)
	g.Observe(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", 1)

	next, pending := g.Stats(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb")
	if next != 2 {
		t.Errorf("next nonce = %d; want 2", next)
	}
	if pending != 2 {
		t.Errorf("pending = %d; want 2", pending)
	}

	// Simulate nonce 0 being confirmed.
	g.Advance(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb", 0)
	next2, pending2 := g.Stats(ChainEthereum, "0xd8da6bf26964af9d7eed9e03e53415d87aa480bb")
	if next2 != 1 {
		t.Errorf("after advance: next nonce = %d; want 1", next2)
	}
	if pending2 != 1 {
		t.Errorf("after advance: pending = %d; want 1", pending2)
	}
}

func TestValueGuard_Check(t *testing.T) {
	g := &ValueGuard{WarnETH: 0.1, DenyETH: 1.0}

	// Zero value — should be fine.
	deny, _ := g.Check(big.NewInt(0))
	if deny {
		t.Error("zero value: expected allow, got deny")
	}

	// 0.05 ETH — warn only.
	deny, reason := g.Check(hexToBigInt("0x6b05c95d2d830000")) // 0.05 ETH
	if deny {
		t.Errorf("warn threshold: got deny=%v, reason=%q; want allow", deny, reason)
	}

	// 2 ETH — deny.
	wei := new(big.Int).Mul(big.NewInt(1e18), big.NewInt(2))
	deny, reason = g.Check(wei)
	if !deny {
		t.Error("deny threshold: got allow; want deny")
	}
	if reason == "" {
		t.Error("deny threshold: expected reason, got empty")
	}
}
