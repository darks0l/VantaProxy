package proxy

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateBodyForAudit_NilBody(t *testing.T) {
	result := truncateBodyForAudit(nil)
	if result != "" {
		t.Errorf("expected empty string for nil body, got %q", result)
	}
}

func TestTruncateBodyForAudit_EmptyBody(t *testing.T) {
	result := truncateBodyForAudit([]byte{})
	if result != "" {
		t.Errorf("expected empty string for empty body, got %q", result)
	}
}

func TestTruncateBodyForAudit_SmallBody(t *testing.T) {
	body := []byte("hello world")
	result := truncateBodyForAudit(body)
	if result != "hello world" {
		t.Errorf("expected %q, got %q", "hello world", result)
	}
}

func TestTruncateBodyForAudit_ExactlyAtLimit(t *testing.T) {
	body := bytes.Repeat([]byte("A"), maxAuditBodySize)
	result := truncateBodyForAudit(body)
	if result != string(body) {
		t.Errorf("body exactly at limit should not be truncated")
	}
	if strings.Contains(result, "[truncated") {
		t.Error("body exactly at limit should not contain truncation marker")
	}
}

func TestTruncateBodyForAudit_OneBytePastLimit(t *testing.T) {
	body := bytes.Repeat([]byte("B"), maxAuditBodySize+1)
	result := truncateBodyForAudit(body)
	if !strings.Contains(result, "[truncated") {
		t.Fatal("expected truncation marker for body exceeding limit")
	}
	expectedMarker := fmt.Sprintf("\n[truncated: %d bytes total, showing first %d]", maxAuditBodySize+1, maxAuditBodySize)
	if !strings.HasSuffix(result, expectedMarker) {
		t.Errorf("unexpected marker, got suffix %q", result[len(result)-80:])
	}
	// The data portion should be exactly maxAuditBodySize bytes of 'B'.
	dataEnd := strings.Index(result, "\n[truncated")
	if dataEnd != maxAuditBodySize {
		t.Errorf("expected %d bytes of data before marker, got %d", maxAuditBodySize, dataEnd)
	}
}

func TestTruncateBodyForAudit_LargeBody(t *testing.T) {
	body := bytes.Repeat([]byte("X"), 10*1024*1024) // 10MB
	result := truncateBodyForAudit(body)
	if !strings.Contains(result, "[truncated") {
		t.Fatal("expected truncation marker for 10MB body")
	}
	expectedMarker := fmt.Sprintf("\n[truncated: %d bytes total, showing first %d]", 10*1024*1024, maxAuditBodySize)
	if !strings.HasSuffix(result, expectedMarker) {
		t.Errorf("unexpected marker suffix")
	}
}

func TestTruncateBodyForAudit_UTF8BoundaryTwoByte(t *testing.T) {
	// Build a body where a 2-byte UTF-8 character straddles maxAuditBodySize.
	// U+00E9 (e-acute) is encoded as 0xC3 0xA9 (2 bytes).
	prefix := bytes.Repeat([]byte("A"), maxAuditBodySize-1)
	// Place e-acute so its first byte is at index maxAuditBodySize-1 and
	// its second byte is at index maxAuditBodySize, which would be split.
	body := append(prefix, []byte("é")...)
	body = append(body, bytes.Repeat([]byte("Z"), 100)...) // ensure over limit

	result := truncateBodyForAudit(body)
	if !utf8.ValidString(result) {
		t.Error("result contains invalid UTF-8")
	}
	if !strings.Contains(result, "[truncated") {
		t.Fatal("expected truncation marker")
	}
	// The function should have backed up, so the data portion should be
	// maxAuditBodySize-1 bytes (the 'A' prefix, without the split rune).
	dataEnd := strings.Index(result, "\n[truncated")
	if dataEnd != maxAuditBodySize-1 {
		t.Errorf("expected %d bytes of data (backed up 1 byte to avoid split), got %d", maxAuditBodySize-1, dataEnd)
	}
}

func TestTruncateBodyForAudit_UTF8BoundaryThreeByte(t *testing.T) {
	// U+4E16 (CJK character) is encoded as 3 bytes: 0xE4 0xB8 0x96.
	// Place it so the first byte is at maxAuditBodySize-2, meaning bytes
	// at indices -2, -1, and maxAuditBodySize. The third byte would be cut.
	prefix := bytes.Repeat([]byte("A"), maxAuditBodySize-2)
	body := append(prefix, []byte("世")...)
	body = append(body, bytes.Repeat([]byte("Z"), 100)...)

	result := truncateBodyForAudit(body)
	if !utf8.ValidString(result) {
		t.Error("result contains invalid UTF-8")
	}
	if !strings.Contains(result, "[truncated") {
		t.Fatal("expected truncation marker")
	}
	// Should back up to exclude the partial 3-byte character.
	dataEnd := strings.Index(result, "\n[truncated")
	if dataEnd != maxAuditBodySize-2 {
		t.Errorf("expected %d bytes of data (backed up 2 bytes to avoid split), got %d", maxAuditBodySize-2, dataEnd)
	}
}

func TestTruncateBodyForAudit_UTF8BoundaryFourByte(t *testing.T) {
	// U+1F600 (grinning face emoji) is 4 bytes: 0xF0 0x9F 0x98 0x80.
	// Place it starting at maxAuditBodySize-3, so the 4th byte would be cut.
	prefix := bytes.Repeat([]byte("A"), maxAuditBodySize-3)
	emoji := "\U0001F600"
	body := append(prefix, []byte(emoji)...)
	body = append(body, bytes.Repeat([]byte("Z"), 100)...)

	result := truncateBodyForAudit(body)
	if !utf8.ValidString(result) {
		t.Error("result contains invalid UTF-8")
	}
	if !strings.Contains(result, "[truncated") {
		t.Fatal("expected truncation marker")
	}
	dataEnd := strings.Index(result, "\n[truncated")
	if dataEnd != maxAuditBodySize-3 {
		t.Errorf("expected %d bytes of data (backed up 3 bytes to avoid split), got %d", maxAuditBodySize-3, dataEnd)
	}
}

func TestTruncateBodyForAudit_UTF8CharFitsExactly(t *testing.T) {
	// When a multi-byte character ends exactly at maxAuditBodySize, it
	// should NOT be removed. Use a 2-byte char ending at the limit.
	prefix := bytes.Repeat([]byte("A"), maxAuditBodySize-2)
	body := append(prefix, []byte("é")...)           // 2 bytes, ending at index maxAuditBodySize
	body = append(body, bytes.Repeat([]byte("Z"), 100)...) // push over limit

	result := truncateBodyForAudit(body)
	if !utf8.ValidString(result) {
		t.Error("result contains invalid UTF-8")
	}
	dataEnd := strings.Index(result, "\n[truncated")
	// The character fits: data should be exactly maxAuditBodySize bytes.
	if dataEnd != maxAuditBodySize {
		t.Errorf("expected %d bytes of data (char fits exactly), got %d", maxAuditBodySize, dataEnd)
	}
}

func TestTruncateBodyForAudit_MarkerIncludesOriginalSize(t *testing.T) {
	totalSize := maxAuditBodySize + 5000
	body := bytes.Repeat([]byte("D"), totalSize)
	result := truncateBodyForAudit(body)
	expected := fmt.Sprintf("[truncated: %d bytes total, showing first %d]", totalSize, maxAuditBodySize)
	if !strings.Contains(result, expected) {
		t.Errorf("marker should include original size info, got: %s", result[len(result)-100:])
	}
}
