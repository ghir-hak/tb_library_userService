package lib

import (
	"strings"
)

// ValidateUpdateProfileRequest validates the update profile request
func ValidateUpdateProfileRequest(req *UpdateProfileRequest) error {
	if req.Name != "" && len(strings.TrimSpace(req.Name)) == 0 {
		return NewHTTPError("name cannot be empty or whitespace only", 400)
	}
	if req.Email != "" {
		email := strings.TrimSpace(req.Email)
		if len(email) == 0 {
			return NewHTTPError("email cannot be empty or whitespace only", 400)
		}
		if !isValidEmail(email) {
			return NewHTTPError("invalid email format", 400)
		}
	}
	return nil
}

// ValidateChangePasswordRequest validates the change password request
func ValidateChangePasswordRequest(req *ChangePasswordRequest) error {
	password := strings.TrimSpace(req.NewPassword)
	if password == "" {
		return NewHTTPError("new password cannot be empty", 400)
	}
	if len(password) < 6 {
		return NewHTTPError("password must be at least 6 characters long", 400)
	}
	return nil
}

// ValidateUpdatePreferencesRequest validates the update preferences request
func ValidateUpdatePreferencesRequest(req *UpdatePreferencesRequest) error {
	if req.DisplayMode != "" {
		displayMode := strings.TrimSpace(strings.ToLower(req.DisplayMode))
		if displayMode != "light" && displayMode != "dark" {
			return NewHTTPError("displayMode must be 'light' or 'dark'", 400)
		}
	}
	return nil
}

// isValidEmail performs basic email validation
func isValidEmail(email string) bool {
	if len(email) < 3 {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	if len(parts[0]) == 0 || len(parts[1]) == 0 {
		return false
	}
	if !strings.Contains(parts[1], ".") {
		return false
	}
	return true
}

