package lib

import (
	"strings"

	"github.com/taubyte/go-sdk/event"
	http "github.com/taubyte/go-sdk/http/event"
)

//export getUserProfile
func getUserProfile(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}

	return handleRequest(h, func(h http.Event, userID string) (interface{}, error) {
		// Get user profile
		profile, err := getUserProfileFromDB(userID)
		if err != nil {
			// If profile doesn't exist, create a default one
			profile = createDefaultProfile(userID, "", "")
			if err := saveUserProfile(*profile); err != nil {
				return nil, NewHTTPError("failed to create default profile", 500)
			}
		}

		return profile, nil
	}, true)
}

//export updateUserProfile
func updateUserProfile(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}

	return handleRequest(h, func(h http.Event, userID string) (interface{}, error) {
		// Decode request body
		var req UpdateProfileRequest
		if err := decodeRequestBody(h, &req); err != nil {
			return nil, err
		}

		// Validate request
		if err := ValidateUpdateProfileRequest(&req); err != nil {
			return nil, err
		}

		// Get existing profile or create default
		profile, err := getUserProfileFromDB(userID)
		if err != nil {
			profile = createDefaultProfile(userID, "", "")
		}

		// Update fields if provided
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

		// Save updated profile
		if err := saveUserProfile(*profile); err != nil {
			return nil, NewHTTPError("failed to update profile", 500)
		}

		return profile, nil
	}, true)
}

//export changePassword
func changePassword(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}

	return handleRequest(h, func(h http.Event, userID string) (interface{}, error) {
		// Decode request body
		var req ChangePasswordRequest
		if err := decodeRequestBody(h, &req); err != nil {
			return nil, err
		}

		// Validate request
		if err := ValidateChangePasswordRequest(&req); err != nil {
			return nil, err
		}

		// Hash new password
		hashedPassword, err := hashPassword(req.NewPassword)
		if err != nil {
			return nil, NewHTTPError("failed to hash password", 500)
		}

		// Update password in auth service database
		if err := updatePasswordInAuthDB(userID, hashedPassword); err != nil {
			return nil, NewHTTPError("failed to update password", 500)
		}

		return map[string]string{"message": "password changed successfully"}, nil
	}, true)
}

//export updatePreferences
func updatePreferences(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}

	return handleRequest(h, func(h http.Event, userID string) (interface{}, error) {
		// Decode request body
		var req UpdatePreferencesRequest
		if err := decodeRequestBody(h, &req); err != nil {
			return nil, err
		}

		// Validate request
		if err := ValidateUpdatePreferencesRequest(&req); err != nil {
			return nil, err
		}

		// Get existing profile or create default
		profile, err := getUserProfileFromDB(userID)
		if err != nil {
			profile = createDefaultProfile(userID, "", "")
		}

		// Update preferences if provided
		if req.Language != "" {
			profile.Preferences.Language = strings.TrimSpace(req.Language)
		}
		if req.Notifications != nil {
			profile.Preferences.Notifications = req.Notifications
		}
		if req.DisplayMode != "" {
			displayMode := strings.TrimSpace(strings.ToLower(req.DisplayMode))
			profile.Preferences.DisplayMode = displayMode
		}

		// Save updated profile
		if err := saveUserProfile(*profile); err != nil {
			return nil, NewHTTPError("failed to update preferences", 500)
		}

		return profile, nil
	}, true)
}
