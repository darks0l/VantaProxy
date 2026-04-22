package web3

import (
	"fmt"
	"math/big"
	"sync"
	"time"
)

// NonceGuard tracks per-address nonce state to detect nonce collision attacks
// and stuck transactions. It is safe for concurrent use.
type NonceGuard struct {
	mu         sync.RWMutex
	nonces     map[string]*nonceState // keyed by "chainID:address" (lower-case)
	maxEntries int                    // eviction threshold
}

// nonceState tracks the last known nonce and pending count.
type nonceState struct {
	NextNonce uint64
	Pending   int
	UpdatedAt time.Time
}

// NewNonceGuard creates a new guard with the given max entries before eviction.
func NewNonceGuard(maxEntries int) *NonceGuard {
	return &NonceGuard{
		nonces:     make(map[string]*nonceState),
		maxEntries: maxEntries,
	}
}

// key builds the internal map key for chain/address.
func key(chainID ChainID, address string) string {
	return fmt.Sprintf("%d:%s", chainID, address)
}

// Observe records that the given nonce was just broadcast for address.
func (g *NonceGuard) Observe(chainID ChainID, address string, nonce uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	k := key(chainID, address)
	state, ok := g.nonces[k]
	if !ok {
		g.nonces[k] = &nonceState{NextNonce: nonce + 1, Pending: 1, UpdatedAt: time.Now()}
		return
	}

	if nonce >= state.NextNonce {
		state.NextNonce = nonce + 1
		state.Pending++
		state.UpdatedAt = time.Now()
	}

	// Evict if over threshold.
	if len(g.nonces) > g.maxEntries {
		g.evictOldest(10)
	}
}

// Check verifies that the proposed nonce is valid and returns an error if it
// would create a gap (indicating a stuck or dropped transaction) or if it
// reuses a known nonce (nonce collision attack).
func (g *NonceGuard) Check(chainID ChainID, address string, proposedNonce uint64) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	k := key(chainID, address)
	state, ok := g.nonces[k]
	if !ok {
		return nil // First transaction for this address; no history.
	}

	// Gap check: if the proposed nonce is more than 1 above our tracked next nonce,
	// there is a missing transaction (likely dropped and needs replacement).
	if proposedNonce > state.NextNonce {
		return fmt.Errorf("nonce gap detected: last known next nonce=%d, proposed=%d (missing=%d); wait for pending transactions or use nonce %d",
			state.NextNonce, proposedNonce, proposedNonce-state.NextNonce, state.NextNonce)
	}

	// Reuse check: if proposed nonce < next nonce, it's a duplicate broadcast.
	if proposedNonce < state.NextNonce {
		return fmt.Errorf("nonce reuse detected: already broadcast nonce %d; next fresh nonce is %d",
			proposedNonce, state.NextNonce)
	}

	return nil
}

// Advance marks a pending transaction as confirmed (it is no longer pending).
// Call this when a transaction receipt shows status=1.
func (g *NonceGuard) Advance(chainID ChainID, address string, confirmedNonce uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	k := key(chainID, address)
	state, ok := g.nonces[k]
	if !ok || confirmedNonce >= state.NextNonce {
		return
	}
	state.NextNonce = confirmedNonce + 1
	if state.Pending > 0 {
		state.Pending--
	}
	state.UpdatedAt = time.Now()
}

// Stats returns the current state for an address.
func (g *NonceGuard) Stats(chainID ChainID, address string) (nextNonce uint64, pending int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	k := key(chainID, address)
	state, ok := g.nonces[k]
	if !ok {
		return 0, 0
	}
	return state.NextNonce, state.Pending
}

// evictOldest removes the oldest N entries by UpdatedAt.
func (g *NonceGuard) evictOldest(n int) {
	type entry struct {
		key  string
		time time.Time
	}
	var entries []entry
	for k, v := range g.nonces {
		entries = append(entries, entry{key: k, time: v.UpdatedAt})
	}

	// Simple selection: remove n oldest.
	for i := 0; i < n && len(entries) > 0; i++ {
		oldest := 0
		for j := 1; j < len(entries); j++ {
			if entries[j].time.Before(entries[oldest].time) {
				oldest = j
			}
		}
		delete(g.nonces, entries[oldest].key)
		entries = append(entries[:oldest], entries[oldest+1:]...)
	}
}

// ValueGuard checks ETH transfer values against configured thresholds.
type ValueGuard struct {
	WarnETH float64 // warn above this
	DenyETH float64 // deny above this
}

// Check returns an error if value exceeds thresholds.
func (g *ValueGuard) Check(value *big.Int) (deny bool, reason string) {
	if value == nil || value.Sign() == 0 {
		return false, ""
	}
	eth := toEth(value)
	if g.DenyETH > 0 && eth >= g.DenyETH {
		return true, fmt.Sprintf("value %.4f ETH exceeds deny threshold %.4f", eth, g.DenyETH)
	}
	if g.WarnETH > 0 && eth >= g.WarnETH {
		return true, fmt.Sprintf("value %.4f ETH exceeds warn threshold %.4f", eth, g.WarnETH)
	}
	return false, ""
}
