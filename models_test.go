package lib

import (
	"encoding/json"
	"testing"
)

func TestUserProfileJSON(t *testing.T) {
	notifications := true
	profile := UserProfile{
		ID:      "user123",
		Name:    "John Doe",
		Email:   "john@example.com",
		Phone:   "1234567890",
		Address: "123 Main St",
		Preferences: Preferences{
			Language:      "en",
			Notifications: &notifications,
			DisplayMode:   "light",
		},
		Roles: []string{"buyer", "seller"},
	}

	// Test marshaling
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("Failed to marshal profile: %v", err)
	}

	// Test unmarshaling
	var unmarshaled UserProfile
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal profile: %v", err)
	}

	if unmarshaled.ID != profile.ID {
		t.Errorf("ID mismatch: got %s, want %s", unmarshaled.ID, profile.ID)
	}
	if unmarshaled.Name != profile.Name {
		t.Errorf("Name mismatch: got %s, want %s", unmarshaled.Name, profile.Name)
	}
	if unmarshaled.Email != profile.Email {
		t.Errorf("Email mismatch: got %s, want %s", unmarshaled.Email, profile.Email)
	}
}

func TestCreateDefaultProfile(t *testing.T) {
	profile := createDefaultProfile("user123", "John Doe", "john@example.com")

	if profile.ID != "user123" {
		t.Errorf("ID mismatch: got %s, want user123", profile.ID)
	}
	if profile.Name != "John Doe" {
		t.Errorf("Name mismatch: got %s, want John Doe", profile.Name)
	}
	if profile.Email != "john@example.com" {
		t.Errorf("Email mismatch: got %s, want john@example.com", profile.Email)
	}
	if profile.Preferences.Language != "en" {
		t.Errorf("Language mismatch: got %s, want en", profile.Preferences.Language)
	}
	if profile.Preferences.DisplayMode != "light" {
		t.Errorf("DisplayMode mismatch: got %s, want light", profile.Preferences.DisplayMode)
	}
	if profile.Preferences.Notifications == nil || !*profile.Preferences.Notifications {
		t.Error("Notifications should be true by default")
	}
	if len(profile.Roles) != 1 || profile.Roles[0] != "buyer" {
		t.Errorf("Roles mismatch: got %v, want [buyer]", profile.Roles)
	}
}

