package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestParseScopes(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "openid profile email",
			expected: []string{"openid", "profile", "email"},
		},
		{
			input:    "openid   profile   openid",
			expected: []string{"openid", "profile"},
		},
		{
			input:    "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		got := parseScopes(tt.input)
		if len(got) != len(tt.expected) {
			t.Fatalf("parseScopes(%q) length = %d; want %d", tt.input, len(got), len(tt.expected))
		}
		for i := range got {
			if got[i] != tt.expected[i] {
				t.Errorf("parseScopes(%q)[%d] = %q; want %q", tt.input, i, got[i], tt.expected[i])
			}
		}
	}
}

func TestMergeScopes(t *testing.T) {
	merged := mergeScopes("openid profile", "profile email custom:read")
	expected := "openid profile email custom:read"
	if merged != expected {
		t.Errorf("mergeScopes() = %q; want %q", merged, expected)
	}
}

func TestTranslateScope(t *testing.T) {
	item := translateScope("openid")
	if item.Title != "View your account ID" {
		t.Errorf("translateScope(openid).Title = %q; want %q", item.Title, "View your account ID")
	}

	itemEmail := translateScope("email")
	if itemEmail.Title != "View your email address" {
		t.Errorf("translateScope(email).Title = %q; want %q", itemEmail.Title, "View your email address")
	}

	itemCustom := translateScope("read:data")
	if itemCustom.Title == "" {
		t.Errorf("translateScope(read:data).Title should not be empty")
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !verifyPKCE(challenge, verifier) {
		t.Errorf("verifyPKCE failed for valid challenge and verifier")
	}

	if verifyPKCE(challenge, "wrong_verifier") {
		t.Errorf("verifyPKCE succeeded for invalid verifier")
	}
}
