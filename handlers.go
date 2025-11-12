package lib

import (
	"encoding/json"
	"strings"

	"github.com/taubyte/go-sdk/event"
)

//export getUserProfile
func getUserProfile(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	// Authenticate
	tokenUserID, retCode := authenticate(h)
	if retCode != 0 {
		return retCode
	}

	// Extract user ID from query parameters
	pathUserID, err := extractQueryParam(h, "id")
	if err != nil {
		return sendErrorResponse(h, "missing or invalid 'id' query parameter", 400)
	}

	// Verify user can only access their own profile
	if tokenUserID != pathUserID {
		return sendErrorResponse(h, "unauthorized: can only access your own profile", 403)
	}

	// Get user profile
	profile, err := getUserProfileFromDB(pathUserID)
	if err != nil {
		// If profile doesn't exist, create a default one
		// This allows the profile to be created on first access
		// In a real scenario, you might want to get basic info from auth service
		profile = createDefaultProfile(pathUserID, "", "")
		if err := saveUserProfile(*profile); err != nil {
			return sendErrorResponse(h, "failed to create default profile", 500)
		}
	}

	return sendJSONResponse(h, profile)
}

//export updateUserProfile
func updateUserProfile(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	// Authenticate
	tokenUserID, retCode := authenticate(h)
	if retCode != 0 {
		return retCode
	}

	// Extract user ID from query parameters
	pathUserID, err := extractQueryParam(h, "id")
	if err != nil {
		return sendErrorResponse(h, "missing or invalid 'id' query parameter", 400)
	}

	// Verify user can only update their own profile
	if tokenUserID != pathUserID {
		return sendErrorResponse(h, "unauthorized: can only update your own profile", 403)
	}

	// Decode request body
	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req UpdateProfileRequest
	if err := reqDec.Decode(&req); err != nil {
		return sendErrorResponse(h, "invalid request format", 400)
	}

	// Get existing profile or create default
	profile, err := getUserProfileFromDB(pathUserID)
	if err != nil {
		profile = createDefaultProfile(pathUserID, "", "")
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
		return sendErrorResponse(h, "failed to update profile", 500)
	}

	return sendJSONResponse(h, profile)
}

//export changePassword
func changePassword(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	// Authenticate
	tokenUserID, retCode := authenticate(h)
	if retCode != 0 {
		return retCode
	}

	// Extract user ID from query parameters
	pathUserID, err := extractQueryParam(h, "id")
	if err != nil {
		return sendErrorResponse(h, "missing or invalid 'id' query parameter", 400)
	}

	// Verify user can only change their own password
	if tokenUserID != pathUserID {
		return sendErrorResponse(h, "unauthorized: can only change your own password", 403)
	}

	// Decode request body
	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req ChangePasswordRequest
	if err := reqDec.Decode(&req); err != nil {
		return sendErrorResponse(h, "invalid request format", 400)
	}

	// Validate new password
	req.NewPassword = strings.TrimSpace(req.NewPassword)
	if req.NewPassword == "" {
		return sendErrorResponse(h, "new password cannot be empty", 400)
	}

	// Hash new password
	hashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		return sendErrorResponse(h, "failed to hash password", 500)
	}

	// Update password in auth service database
	// The auth service stores users at /users/id/{id} and /users/{username}
	// We need to update both locations to keep them in sync
	if err := updatePasswordInAuthDB(pathUserID, hashedPassword); err != nil {
		return sendErrorResponse(h, "failed to update password", 500)
	}

	response := map[string]string{"message": "password changed successfully"}
	return sendJSONResponse(h, response)
}

//export updatePreferences
func updatePreferences(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	// Authenticate
	tokenUserID, retCode := authenticate(h)
	if retCode != 0 {
		return retCode
	}

	// Extract user ID from query parameters
	pathUserID, err := extractQueryParam(h, "id")
	if err != nil {
		return sendErrorResponse(h, "missing or invalid 'id' query parameter", 400)
	}

	// Verify user can only update their own preferences
	if tokenUserID != pathUserID {
		return sendErrorResponse(h, "unauthorized: can only update your own preferences", 403)
	}

	// Decode request body
	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req UpdatePreferencesRequest
	if err := reqDec.Decode(&req); err != nil {
		return sendErrorResponse(h, "invalid request format", 400)
	}

	// Get existing profile or create default
	profile, err := getUserProfileFromDB(pathUserID)
	if err != nil {
		profile = createDefaultProfile(pathUserID, "", "")
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
		if displayMode != "light" && displayMode != "dark" {
			return sendErrorResponse(h, "displayMode must be 'light' or 'dark'", 400)
		}
		profile.Preferences.DisplayMode = displayMode
	}

	// Save updated profile
	if err := saveUserProfile(*profile); err != nil {
		return sendErrorResponse(h, "failed to update preferences", 500)
	}

	return sendJSONResponse(h, profile)
}

