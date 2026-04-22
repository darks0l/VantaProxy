package proxy

import (
	"testing"
)

func TestExtractProxyAuth(t *testing.T) {
	tests := []struct {
		name             string
		header           string
		wantGatewayToken string
		wantErr          bool
	}{
		{
			name:             "empty header returns no error",
			header:           "",
			wantGatewayToken: "",
			wantErr:          false,
		},
		{
			name:             "Basic with gat_ token",
			header:           "Basic Z2F0X2FiYzEyMzo=", // gat_abc123:
			wantGatewayToken: "gat_abc123",
			wantErr:          false,
		},
		{
			name:             "Basic with non-gat username",
			header:           "Basic cGxhaW51c2VyOg==", // plainuser:
			wantGatewayToken: "",
			wantErr:          false,
		},
		{
			name:             "basic lowercase scheme is accepted",
			header:           "basic Z2F0X2FiYzEyMzo=", // gat_abc123:
			wantGatewayToken: "gat_abc123",
			wantErr:          false,
		},
		{
			name:             "BASIC uppercase scheme is accepted",
			header:           "BASIC Z2F0X2FiYzEyMzo=", // gat_abc123:
			wantGatewayToken: "gat_abc123",
			wantErr:          false,
		},
		{
			name:             "BaSiC mixed case scheme is accepted",
			header:           "BaSiC Z2F0X2FiYzEyMzo=", // gat_abc123:
			wantGatewayToken: "gat_abc123",
			wantErr:          false,
		},
		{
			name:    "Bearer token returns error",
			header:  "Bearer eyJhbGciOiJIUzI1NiJ9",
			wantErr: true,
		},
		{
			name:    "Digest scheme returns error",
			header:  "Digest username=\"admin\"",
			wantErr: true,
		},
		{
			name:    "unknown scheme returns error",
			header:  "CustomScheme credentials",
			wantErr: true,
		},
		{
			name:    "scheme only no space returns error",
			header:  "Bearer",
			wantErr: true,
		},
		{
			name:             "Basic with invalid base64 returns no error and empty token",
			header:           "Basic !!!invalid-base64!!!",
			wantGatewayToken: "",
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := extractProxyAuth(tt.header)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for header %q, got nil", tt.header)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error for header %q: %v", tt.header, err)
				return
			}
			if auth.gatewayToken != tt.wantGatewayToken {
				t.Errorf("gatewayToken = %q, want %q", auth.gatewayToken, tt.wantGatewayToken)
			}
		})
	}
}
