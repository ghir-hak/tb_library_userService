package lib

import (
	"encoding/json"
	"strings"

	"github.com/taubyte/go-sdk/event"
	"golang.org/x/crypto/bcrypt"
)

//export getUserProfile
func getUserProfile(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}

	// CORS
	h.Headers().Set("Access-Control-Allow-Origin", "*")
	if method, _ := h.Method(); method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	// Auth
	authHeader, _ := h.Headers().Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		h.Write([]byte(`{"error":"missing authorization header"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(401)
		return 1
	}
	userID, err := ValidateToken(authHeader[7:])
	if err != nil {
		h.Write([]byte(`{"error":"invalid or expired token"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(401)
		return 1
	}

	// Get id from query
	queryID, err := h.Query().Get("id")
	if err != nil || queryID != userID {
		h.Write([]byte(`{"error":"unauthorized"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(403)
		return 1
	}

	// Get profile
	profile, err := getUserProfileFromDB(userID)
	if err != nil {
		notifications := true
		profile = &UserProfile{
			ID: userID, Preferences: Preferences{Language: "en", Notifications: &notifications, DisplayMode: "light"},
			Roles: []string{"buyer"},
		}
		if err := saveUserProfile(*profile); err != nil {
			h.Write([]byte(`{"error":"failed to create profile"}`))
			h.Headers().Set("Content-Type", "application/json")
			h.Return(500)
			return 1
		}
	}

	data, _ := json.Marshal(profile)
	h.Headers().Set("Content-Type", "application/json")
	h.Write(data)
	h.Return(200)
	return 0
}

//export updateUserProfile
func updateUserProfile(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}

	h.Headers().Set("Access-Control-Allow-Origin", "*")
	if method, _ := h.Method(); method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	authHeader, _ := h.Headers().Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		h.Write([]byte(`{"error":"missing authorization header"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(401)
		return 1
	}
	userID, err := ValidateToken(authHeader[7:])
	if err != nil {
		h.Write([]byte(`{"error":"invalid or expired token"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(401)
		return 1
	}

	queryID, err := h.Query().Get("id")
	if err != nil || queryID != userID {
		h.Write([]byte(`{"error":"unauthorized"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(403)
		return 1
	}

	// Check action parameter for routing
	action, _ := h.Query().Get("action")

	// Handle password change
	if action == "password" {
		var req ChangePasswordRequest
		if json.NewDecoder(h.Body()).Decode(&req) != nil {
			h.Write([]byte(`{"error":"invalid request format"}`))
			h.Headers().Set("Content-Type", "application/json")
			h.Return(400)
			return 1
		}
		h.Body().Close()

		if len(strings.TrimSpace(req.NewPassword)) < 6 {
			h.Write([]byte(`{"error":"password must be at least 6 characters"}`))
			h.Headers().Set("Content-Type", "application/json")
			h.Return(400)
			return 1
		}

		hashed, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 10)
		if err := updatePasswordInAuthDB(userID, string(hashed)); err != nil {
			h.Write([]byte(`{"error":"failed to update password"}`))
			h.Headers().Set("Content-Type", "application/json")
			h.Return(500)
			return 1
		}

		h.Write([]byte(`{"message":"password changed successfully"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(200)
		return 0
	}

	// Handle preferences update
	if action == "preferences" {
		var req UpdatePreferencesRequest
		if json.NewDecoder(h.Body()).Decode(&req) != nil {
			h.Write([]byte(`{"error":"invalid request format"}`))
			h.Headers().Set("Content-Type", "application/json")
			h.Return(400)
			return 1
		}
		h.Body().Close()

		if req.DisplayMode != "" {
			dm := strings.ToLower(strings.TrimSpace(req.DisplayMode))
			if dm != "light" && dm != "dark" {
				h.Write([]byte(`{"error":"displayMode must be 'light' or 'dark'"}`))
				h.Headers().Set("Content-Type", "application/json")
				h.Return(400)
				return 1
			}
		}

		profile, _ := getUserProfileFromDB(userID)
		if profile == nil {
			notifications := true
			profile = &UserProfile{ID: userID, Preferences: Preferences{Language: "en", Notifications: &notifications, DisplayMode: "light"}, Roles: []string{"buyer"}}
		}

		if req.Language != "" {
			profile.Preferences.Language = strings.TrimSpace(req.Language)
		}
		if req.Notifications != nil {
			profile.Preferences.Notifications = req.Notifications
		}
		if req.DisplayMode != "" {
			profile.Preferences.DisplayMode = strings.ToLower(strings.TrimSpace(req.DisplayMode))
		}

		if err := saveUserProfile(*profile); err != nil {
			h.Write([]byte(`{"error":"failed to update preferences"}`))
			h.Headers().Set("Content-Type", "application/json")
			h.Return(500)
			return 1
		}

		data, _ := json.Marshal(profile)
		h.Headers().Set("Content-Type", "application/json")
		h.Write(data)
		h.Return(200)
		return 0
	}

	// Handle profile update (default)
	var req UpdateProfileRequest
	if json.NewDecoder(h.Body()).Decode(&req) != nil {
		h.Write([]byte(`{"error":"invalid request format"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(400)
		return 1
	}
	h.Body().Close()

	if req.Email != "" {
		parts := strings.Split(req.Email, "@")
		if len(parts) != 2 || len(parts[0]) == 0 || !strings.Contains(parts[1], ".") {
			h.Write([]byte(`{"error":"invalid email format"}`))
			h.Headers().Set("Content-Type", "application/json")
			h.Return(400)
			return 1
		}
	}

	profile, _ := getUserProfileFromDB(userID)
	if profile == nil {
		notifications := true
		profile = &UserProfile{ID: userID, Preferences: Preferences{Language: "en", Notifications: &notifications, DisplayMode: "light"}, Roles: []string{"buyer"}}
	}

	if req.Name != "" {
		profile.Name = strings.TrimSpace(req.Name)
	}
	if req.Email != "" {
		profile.Email = strings.TrimSpace(req.Email)
	}
	if req.Phone != "" {
		profile.Phone = strings.TrimSpace(req.Phone)
	}
	if req.Address != "" {
		profile.Address = strings.TrimSpace(req.Address)
	}

	if err := saveUserProfile(*profile); err != nil {
		h.Write([]byte(`{"error":"failed to update profile"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(500)
		return 1
	}

	data, _ := json.Marshal(profile)
	h.Headers().Set("Content-Type", "application/json")
	h.Write(data)
	h.Return(200)
	return 0
}

//export changePassword
func changePassword(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}

	h.Headers().Set("Access-Control-Allow-Origin", "*")
	if method, _ := h.Method(); method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	authHeader, _ := h.Headers().Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		h.Write([]byte(`{"error":"missing authorization header"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(401)
		return 1
	}
	userID, err := ValidateToken(authHeader[7:])
	if err != nil {
		h.Write([]byte(`{"error":"invalid or expired token"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(401)
		return 1
	}

	queryID, err := h.Query().Get("id")
	if err != nil || queryID != userID {
		h.Write([]byte(`{"error":"unauthorized"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(403)
		return 1
	}

	var req ChangePasswordRequest
	if json.NewDecoder(h.Body()).Decode(&req) != nil {
		h.Write([]byte(`{"error":"invalid request format"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(400)
		return 1
	}
	h.Body().Close()

	if len(strings.TrimSpace(req.NewPassword)) < 6 {
		h.Write([]byte(`{"error":"password must be at least 6 characters"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(400)
		return 1
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 10)
	if err := updatePasswordInAuthDB(userID, string(hashed)); err != nil {
		h.Write([]byte(`{"error":"failed to update password"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(500)
		return 1
	}

	h.Write([]byte(`{"message":"password changed successfully"}`))
	h.Headers().Set("Content-Type", "application/json")
	h.Return(200)
	return 0
}

//export updatePreferences
func updatePreferences(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}

	h.Headers().Set("Access-Control-Allow-Origin", "*")
	if method, _ := h.Method(); method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	authHeader, _ := h.Headers().Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		h.Write([]byte(`{"error":"missing authorization header"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(401)
		return 1
	}
	userID, err := ValidateToken(authHeader[7:])
	if err != nil {
		h.Write([]byte(`{"error":"invalid or expired token"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(401)
		return 1
	}

	queryID, err := h.Query().Get("id")
	if err != nil || queryID != userID {
		h.Write([]byte(`{"error":"unauthorized"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(403)
		return 1
	}

	var req UpdatePreferencesRequest
	if json.NewDecoder(h.Body()).Decode(&req) != nil {
		h.Write([]byte(`{"error":"invalid request format"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(400)
		return 1
	}
	h.Body().Close()

	if req.DisplayMode != "" {
		dm := strings.ToLower(strings.TrimSpace(req.DisplayMode))
		if dm != "light" && dm != "dark" {
			h.Write([]byte(`{"error":"displayMode must be 'light' or 'dark'"}`))
			h.Headers().Set("Content-Type", "application/json")
			h.Return(400)
			return 1
		}
	}

	profile, _ := getUserProfileFromDB(userID)
	if profile == nil {
		notifications := true
		profile = &UserProfile{ID: userID, Preferences: Preferences{Language: "en", Notifications: &notifications, DisplayMode: "light"}, Roles: []string{"buyer"}}
	}

	if req.Language != "" {
		profile.Preferences.Language = strings.TrimSpace(req.Language)
	}
	if req.Notifications != nil {
		profile.Preferences.Notifications = req.Notifications
	}
	if req.DisplayMode != "" {
		profile.Preferences.DisplayMode = strings.ToLower(strings.TrimSpace(req.DisplayMode))
	}

	if err := saveUserProfile(*profile); err != nil {
		h.Write([]byte(`{"error":"failed to update preferences"}`))
		h.Headers().Set("Content-Type", "application/json")
		h.Return(500)
		return 1
	}

	data, _ := json.Marshal(profile)
	h.Headers().Set("Content-Type", "application/json")
	h.Write(data)
	h.Return(200)
	return 0
}
