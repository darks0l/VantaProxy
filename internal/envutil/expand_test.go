package envutil

import (
	"os"
	"testing"
)

func TestExpandWithStatusPartialReference(t *testing.T) {
	os.Setenv("TEST_PREFIX", "Bearer ")
	os.Setenv("TEST_TOKEN", "abc123")
	defer func() {
		os.Unsetenv("TEST_PREFIX")
		os.Unsetenv("TEST_TOKEN")
	}()

	expanded, hadRef, unresolved := ExpandWithStatus("${TEST_PREFIX}${TEST_TOKEN}")
	if expanded != "Bearer abc123" {
		t.Fatalf("Expected expanded value, got %q", expanded)
	}
	if !hadRef {
		t.Fatal("Expected hadRef=true")
	}
	if unresolved {
		t.Fatal("Expected unresolved=false")
	}
}

func TestExpandWithStatusUnresolvedPartialReference(t *testing.T) {
	os.Setenv("TEST_PREFIX", "Bearer ")
	os.Unsetenv("TEST_MISSING")
	defer os.Unsetenv("TEST_PREFIX")

	expanded, hadRef, unresolved := ExpandWithStatus("${TEST_PREFIX}${TEST_MISSING}")
	if expanded != "Bearer " {
		t.Fatalf("Expected partial expansion with missing suffix, got %q", expanded)
	}
	if !hadRef {
		t.Fatal("Expected hadRef=true")
	}
	if !unresolved {
		t.Fatal("Expected unresolved=true")
	}
}

func TestContainsEnvReference(t *testing.T) {
	if !ContainsEnvReference("${TOKEN}") {
		t.Fatal("Expected single braced env ref to be detected")
	}
	if !ContainsEnvReference("prefix-${TOKEN}") {
		t.Fatal("Expected embedded braced env ref to be detected")
	}
	if !ContainsEnvReference("$TOKEN") {
		t.Fatal("Expected full dollar env ref to be detected")
	}
	if ContainsEnvReference("tok$en") {
		t.Fatal("Expected literal dollar string to not be detected as env ref")
	}
}
