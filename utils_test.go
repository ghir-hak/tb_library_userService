package lib

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "testpassword123"
	hashed, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword failed: %v", err)
	}

	if hashed == "" {
		t.Error("hashed password should not be empty")
	}

	if hashed == password {
		t.Error("hashed password should not equal original password")
	}
}

func TestComparePassword(t *testing.T) {
	password := "testpassword123"
	hashed, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword failed: %v", err)
	}

	// Test correct password
	if !comparePassword(hashed, password) {
		t.Error("comparePassword should return true for correct password")
	}

	// Test incorrect password
	if comparePassword(hashed, "wrongpassword") {
		t.Error("comparePassword should return false for incorrect password")
	}

	// Test empty password
	if comparePassword(hashed, "") {
		t.Error("comparePassword should return false for empty password")
	}

	// Test invalid hash
	if comparePassword("invalidhash", password) {
		t.Error("comparePassword should return false for invalid hash")
	}
}

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email  string
		valid  bool
		reason string
	}{
		{"test@example.com", true, "valid email"},
		{"user.name@domain.co.uk", true, "valid email with subdomain"},
		{"invalid", false, "missing @"},
		{"invalid@", false, "missing domain"},
		{"@domain.com", false, "missing local part"},
		{"test@domain", false, "missing TLD"},
		{"", false, "empty string"},
		{"a@b.c", true, "minimal valid email"},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			result := isValidEmail(tt.email)
			if result != tt.valid {
				t.Errorf("isValidEmail(%q) = %v, want %v", tt.email, result, tt.valid)
			}
		})
	}
}

