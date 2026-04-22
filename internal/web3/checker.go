package web3

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HealthCheckResult holds the result of an RPC health check.
type HealthCheckResult struct {
	RPCURL     string  // The URL that was checked.
	OK         bool    // Whether the RPC responded correctly.
	LatencyMs  int64   // Observed round-trip latency in milliseconds.
	ChainID    uint64  // Reported chain ID (0 if unavailable).
	Error      string  // Error message if OK==false.
	CheckedAt  time.Time
}

// RPCHealthChecker probes RPC endpoints periodically to verify they are
// reachable, report their latency, and detect chain ID mismatches.
type RPCHealthChecker struct {
	interval time.Duration
	client   *http.Client
	cache    map[string]*HealthCheckResult
	mu       sync.RWMutex
	stop     chan struct{}
}

// NewRPCHealthChecker creates a checker that probes all configured RPC endpoints
// every interval.
func NewRPCHealthChecker(interval time.Duration) *RPCHealthChecker {
	return &RPCHealthChecker{
		interval: interval,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				IdleConnTimeout:     30 * time.Second,
				DisableKeepAlives:    false,
				TLSHandshakeTimeout:  5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
		cache: make(map[string]*HealthCheckResult),
		stop:  make(chan struct{}),
	}
}

// Start begins background probing of all provided RPC configs.
func (c *RPCHealthChecker) Start(rpcs []RPCConfig) {
	go c.run(rpcs)
}

func (c *RPCHealthChecker) run(rpcs []RPCConfig) {
	// Do an immediate check on start.
	c.checkAll(rpcs)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.checkAll(rpcs)
		case <-c.stop:
			return
		}
	}
}

// Stop halts background checking.
func (c *RPCHealthChecker) Stop() {
	close(c.stop)
}

// Get returns the cached health result for url, or nil if not yet checked.
func (c *RPCHealthChecker) Get(url string) *HealthCheckResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache[url]
}

// CheckNow triggers an immediate check of url and returns the result.
func (c *RPCHealthChecker) CheckNow(url string) *HealthCheckResult {
	return c.checkOne(url, 0)
}

// checkAll probes all RPC URLs concurrently.
func (c *RPCHealthChecker) checkAll(rpcs []RPCConfig) {
	var wg sync.WaitGroup
	seen := make(map[string]bool)
	for _, rpc := range rpcs {
		if !rpc.Enabled || rpc.URL == "" {
			continue
		}
		if seen[rpc.URL] {
			continue
		}
		seen[rpc.URL] = true
		wg.Add(1)
		go func(rpcURL string, expectedChain ChainID) {
			defer wg.Done()
			result := c.checkOne(rpcURL, uint64(expectedChain))
			c.mu.Lock()
			c.cache[rpcURL] = result
			c.mu.Unlock()
		}(rpc.URL, rpc.ChainID)
	}
	wg.Wait()
}

// checkOne performs a single eth_blockNumber + eth_chainId probe.
func (c *RPCHealthChecker) checkOne(rpcURL string, expectedChainID uint64) *HealthCheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	result := &HealthCheckResult{RPCURL: rpcURL, CheckedAt: start}

	body, statusCode, err := c.doRPC(ctx, rpcURL, "eth_chainId", []any{})
	if err != nil {
		result.Error = err.Error()
		result.OK = false
		return result
	}
	result.LatencyMs = time.Since(start).Milliseconds()
	result.OK = statusCode == 200

	if !result.OK {
		result.Error = fmt.Sprintf("HTTP %d", statusCode)
		return result
	}

	var chainResp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(body, &chainResp); err != nil {
		result.Error = fmt.Sprintf("invalid JSON response: %v", err)
		result.OK = false
		return result
	}

	chainID, err := parseChainID(chainResp.Result)
	if err != nil {
		result.Error = fmt.Sprintf("invalid chainId: %v", err)
		result.ChainID = 0
		return result
	}
	result.ChainID = chainID

	if expectedChainID > 0 && chainID != expectedChainID {
		result.Error = fmt.Sprintf("chain ID mismatch: expected %d, got %d", expectedChainID, chainID)
		result.OK = false
	}

	return result
}

// doRPC performs a JSON-RPC POST request.
func (c *RPCHealthChecker) doRPC(ctx context.Context, rpcURL, method string, params []any) ([]byte, int, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params": params,
		"id":     1,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	return respBody, resp.StatusCode, nil
}

// readAll reads up to 64KB from r.
func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	for {
		b := make([]byte, 1024)
		n, err := r.Read(b)
		buf = append(buf, b[:n]...)
		if n < 1024 || len(buf) > 64*1024 {
			if err != nil {
				return buf, nil
			}
			return buf, nil
		}
	}
}

// parseChainID parses a 0x-prefixed hex chain ID to uint64.
func parseChainID(s string) (uint64, error) {
	s = strip0x(s)
	var n uint64
	for _, c := range s {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += uint64(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += uint64(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("invalid hex %q", s)
		}
	}
	return n, nil
}

func strip0x(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}
