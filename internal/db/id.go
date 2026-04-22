package db

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewID generates a prefixed random ID, e.g. "user_a1b2c3d4e5f6".
func NewID(prefix string) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("db.NewID: crypto/rand failed: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(b)
}

// NewGatewayAuthToken generates a gateway auth token of the form "gat_" + 32 hex chars (16 bytes entropy).
// Higher entropy than NewID since this is an authentication credential.
func NewGatewayAuthToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("db.NewGatewayAuthToken: crypto/rand failed: %v", err))
	}
	return "gat_" + hex.EncodeToString(b)
}
