package builder

import (
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "numeric path segment",
			input: "/v1/applications/280884604002",
			want:  "/v1/applications/{id}",
		},
		{
			name:  "uuid path segment",
			input: "/v1/users/550e8400-e29b-41d4-a716-446655440000/profile",
			want:  "/v1/users/{uuid}/profile",
		},
		{
			name:  "hash path segment (git SHA)",
			input: "/v1/c5df90ae9d94f2ee63ad0748ab0ee8bab1df0da0df7156290dafa43504f74e70/openclaw",
			want:  "/v1/{hash}/openclaw",
		},
		{
			name:  "token path segment (url-safe base64, >=20 chars)",
			input: "/v1/c5df90ae9d94f2ee63ad0748ab0ee8bab1df0da0df7156290dafa43504f74e70/openclaw/eJyqVgIAAX0AvwZXYZ12",
			want:  "/v1/{hash}/openclaw/{token}",
		},
		{
			name:  "pdf filename normalized",
			input: "https://grnhse-use1-prod-s2-ghr.s3.amazonaws.com/person_attachments/data/1/2/3/4/original/Updated_Resume.pdf",
			want:  "https://grnhse-use1-prod-s2-ghr.s3.amazonaws.com/person_attachments/data/{id}/{id}/{id}/{id}/original/{filename}",
		},
		{
			name:  "url-encoded filename normalized",
			input: "https://example.s3.amazonaws.com/files/123/Yuvadeep%20Reddy%20update.pdf",
			want:  "https://example.s3.amazonaws.com/files/{id}/{filename}",
		},
		{
			name:  "docx filename normalized",
			input: "https://example.s3.amazonaws.com/attachments/1/original/Brex%20Cover%20Letter.docx",
			want:  "https://example.s3.amazonaws.com/attachments/{id}/original/{filename}",
		},
		{
			name:  "hostname with tld not normalized",
			input: "https://registry.npmjs.org/is-url",
			want:  "https://registry.npmjs.org/is-url",
		},
		{
			name:  "static path unchanged",
			input: "/v1/applications",
			want:  "/v1/applications",
		},
		{
			name:  "query timestamp ISO8601 with Z",
			input: "/v1/jobs?created_after=2024-03-26T22:10:33Z&status=active",
			want:  "/v1/jobs?created_after={timestamp}&status=active",
		},
		{
			// In real URLs the + offset must be percent-encoded (%2B); raw + is decoded as space by
			// url.ParseQuery so we normalize only the Z-suffix and percent-encoded offset forms.
			name:  "query timestamp ISO8601 with percent-encoded offset",
			input: "/v1/jobs?created_after=2024-03-26T22:10:33%2B05:00",
			want:  "/v1/jobs?created_after={timestamp}",
		},
		{
			name:  "query integer values",
			input: "/v1/jobs?job_id=6031785002&page=4",
			want:  "/v1/jobs?job_id={number}&page={number}",
		},
		{
			name:  "query uuid value",
			input: "/v1/items?id=550e8400-e29b-41d4-a716-446655440000",
			want:  "/v1/items?id={uuid}",
		},
		{
			name:  "query keys sorted alphabetically",
			input: "/v1/search?z=foo&a=bar",
			want:  "/v1/search?a=bar&z=foo",
		},
		{
			name:  "enum query value left as-is",
			input: "/v1/items?status=active",
			want:  "/v1/items?status=active",
		},
		{
			name:  "root path",
			input: "/",
			want:  "/",
		},
		{
			name:  "no path no query",
			input: "",
			want:  "",
		},
		{
			name:  "short hex not normalized (under 16 chars)",
			input: "/v1/items/abc123",
			want:  "/v1/items/abc123",
		},
		{
			name:  "long hex normalized",
			input: "/v1/items/deadbeefcafebabe0123456789abcdef",
			want:  "/v1/items/{hash}",
		},
		{
			// All-hex segment goes to {hash}; a segment with uppercase letters goes to {token}.
			name:  "mixed path with hex segment becomes hash",
			input: "/api/v2/orgs/42/repos/abc123def456789012345678/commits",
			want:  "/api/v2/orgs/{id}/repos/{hash}/commits",
		},
		{
			name:  "mixed path with mixed-case token segment",
			input: "/api/v2/orgs/42/repos/AbC123XyZ456789012345678/commits",
			want:  "/api/v2/orgs/{id}/repos/{token}/commits",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeURL(tc.input)
			if got != tc.want {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
