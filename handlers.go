package lib

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/taubyte/go-sdk/event"
)

//export getUserProfile
func getUserProfile(e event.Event) uint32 {
	fmt.Printf("DEBUG getUserProfile: handler called\n")
	h, err := e.HTTP()
	if err != nil {
		fmt.Printf("DEBUG getUserProfile: failed to get HTTP event, error = %v\n", err)
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		fmt.Printf("DEBUG getUserProfile: OPTIONS request, returning 200\n")
		h.Return(200)
		return 0
	}

	fmt.Printf("DEBUG getUserProfile: HTTP method = %s\n", method)

	// Authenticate
	tokenUserID, retCode := authenticate(h)
	if retCode != 0 {
		fmt.Printf("DEBUG getUserProfile: authentication failed, retCode = %d\n", retCode)
		return retCode
	}
	fmt.Printf("DEBUG getUserProfile: authenticated userID = %s\n", tokenUserID)

	// Extract user ID from query parameters
	pathUserID, err := extractQueryParam(h, "id")
	if err != nil {
		fmt.Printf("DEBUG getUserProfile: extractQueryParam error = %v\n", err)
		debugMsg := fmt.Sprintf("missing or invalid 'id' query parameter. Error: %v", err)
		return sendErrorResponse(h, debugMsg, 400)
	}
	fmt.Printf("DEBUG getUserProfile: extracted pathUserID = %s\n", pathUserID)

	// Verify user can only access their own profile
	if tokenUserID != pathUserID {
		fmt.Printf("DEBUG getUserProfile: authorization failed - tokenUserID=%s, pathUserID=%s\n", tokenUserID, pathUserID)
		return sendErrorResponse(h, "unauthorized: can only access your own profile", 403)
	}

	// Get user profile
	profile, err := getUserProfileFromDB(pathUserID)
	if err != nil {
		fmt.Printf("DEBUG getUserProfile: profile not found, creating default. Error: %v\n", err)
		// If profile doesn't exist, create a default one
		profile = createDefaultProfile(pathUserID, "", "")
		if err := saveUserProfile(*profile); err != nil {
			fmt.Printf("DEBUG getUserProfile: failed to create default profile. Error: %v\n", err)
			return sendErrorResponse(h, "failed to create default profile", 500)
		}
		fmt.Printf("DEBUG getUserProfile: created default profile\n")
	} else {
		fmt.Printf("DEBUG getUserProfile: found existing profile\n")
	}

	fmt.Printf("DEBUG getUserProfile: returning profile for userID = %s\n", pathUserID)
	return sendJSONResponse(h, profile)
}

//export updateUserProfile
func updateUserProfile(e event.Event) uint32 {
	fmt.Printf("DEBUG updateUserProfile: handler called\n")
	h, err := e.HTTP()
	if err != nil {
		fmt.Printf("DEBUG updateUserProfile: failed to get HTTP event, error = %v\n", err)
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		fmt.Printf("DEBUG updateUserProfile: OPTIONS request, returning 200\n")
		h.Return(200)
		return 0
	}

	fmt.Printf("DEBUG updateUserProfile: HTTP method = %s\n", method)

	// Authenticate
	tokenUserID, retCode := authenticate(h)
	if retCode != 0 {
		fmt.Printf("DEBUG updateUserProfile: authentication failed, retCode = %d\n", retCode)
		return retCode
	}
	fmt.Printf("DEBUG updateUserProfile: authenticated userID = %s\n", tokenUserID)

	// Extract user ID from query parameters
	pathUserID, err := extractQueryParam(h, "id")
	if err != nil {
		fmt.Printf("DEBUG updateUserProfile: extractQueryParam error = %v\n", err)
		debugMsg := fmt.Sprintf("missing or invalid 'id' query parameter. Error: %v", err)
		return sendErrorResponse(h, debugMsg, 400)
	}
	fmt.Printf("DEBUG updateUserProfile: extracted pathUserID = %s\n", pathUserID)

	// Verify user can only update their own profile
	if tokenUserID != pathUserID {
		fmt.Printf("DEBUG updateUserProfile: authorization failed - tokenUserID=%s, pathUserID=%s\n", tokenUserID, pathUserID)
		return sendErrorResponse(h, "unauthorized: can only update your own profile", 403)
	}

	// Decode request body
	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req UpdateProfileRequest
	if err := reqDec.Decode(&req); err != nil {
		fmt.Printf("DEBUG updateUserProfile: failed to decode request body, error = %v\n", err)
		return sendErrorResponse(h, "invalid request format", 400)
	}
	fmt.Printf("DEBUG updateUserProfile: decoded request - Name=%s, Email=%s, Phone=%s, Address=%s\n", req.Name, req.Email, req.Phone, req.Address)

	// Get existing profile or create default
	profile, err := getUserProfileFromDB(pathUserID)
	if err != nil {
		fmt.Printf("DEBUG updateUserProfile: profile not found, creating default. Error: %v\n", err)
		profile = createDefaultProfile(pathUserID, "", "")
	} else {
		fmt.Printf("DEBUG updateUserProfile: found existing profile\n")
	}

	// Update fields if provided
	if req.Name != "" {
		profile.Name = strings.TrimSpace(req.Name)
		fmt.Printf("DEBUG updateUserProfile: updated Name = %s\n", profile.Name)
	}
	if req.Email != "" {
		profile.Email = strings.TrimSpace(req.Email)
		fmt.Printf("DEBUG updateUserProfile: updated Email = %s\n", profile.Email)
	}
	if req.Phone != "" {
		profile.Phone = strings.TrimSpace(req.Phone)
		fmt.Printf("DEBUG updateUserProfile: updated Phone = %s\n", profile.Phone)
	}
	if req.Address != "" {
		profile.Address = strings.TrimSpace(req.Address)
		fmt.Printf("DEBUG updateUserProfile: updated Address = %s\n", profile.Address)
	}

	// Save updated profile
	if err := saveUserProfile(*profile); err != nil {
		fmt.Printf("DEBUG updateUserProfile: failed to save profile, error = %v\n", err)
		return sendErrorResponse(h, "failed to update profile", 500)
	}
	fmt.Printf("DEBUG updateUserProfile: profile saved successfully\n")

	return sendJSONResponse(h, profile)
}

//export changePassword
func changePassword(e event.Event) uint32 {
	fmt.Printf("DEBUG changePassword: handler called\n")
	h, err := e.HTTP()
	if err != nil {
		fmt.Printf("DEBUG changePassword: failed to get HTTP event, error = %v\n", err)
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		fmt.Printf("DEBUG changePassword: OPTIONS request, returning 200\n")
		h.Return(200)
		return 0
	}

	fmt.Printf("DEBUG changePassword: HTTP method = %s\n", method)

	// Authenticate
	tokenUserID, retCode := authenticate(h)
	if retCode != 0 {
		fmt.Printf("DEBUG changePassword: authentication failed, retCode = %d\n", retCode)
		return retCode
	}
	fmt.Printf("DEBUG changePassword: authenticated userID = %s\n", tokenUserID)

	// Extract user ID from query parameters
	pathUserID, err := extractQueryParam(h, "id")
	if err != nil {
		fmt.Printf("DEBUG changePassword: extractQueryParam error = %v\n", err)
		debugMsg := fmt.Sprintf("missing or invalid 'id' query parameter. Error: %v", err)
		return sendErrorResponse(h, debugMsg, 400)
	}
	fmt.Printf("DEBUG changePassword: extracted pathUserID = %s\n", pathUserID)

	// Verify user can only change their own password
	if tokenUserID != pathUserID {
		fmt.Printf("DEBUG changePassword: authorization failed - tokenUserID=%s, pathUserID=%s\n", tokenUserID, pathUserID)
		return sendErrorResponse(h, "unauthorized: can only change your own password", 403)
	}

	// Decode request body
	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req ChangePasswordRequest
	if err := reqDec.Decode(&req); err != nil {
		fmt.Printf("DEBUG changePassword: failed to decode request body, error = %v\n", err)
		return sendErrorResponse(h, "invalid request format", 400)
	}
	fmt.Printf("DEBUG changePassword: decoded request - NewPassword length = %d\n", len(req.NewPassword))

	// Validate new password
	req.NewPassword = strings.TrimSpace(req.NewPassword)
	if req.NewPassword == "" {
		fmt.Printf("DEBUG changePassword: new password is empty\n")
		return sendErrorResponse(h, "new password cannot be empty", 400)
	}

	// Hash new password
	hashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		fmt.Printf("DEBUG changePassword: failed to hash password, error = %v\n", err)
		return sendErrorResponse(h, "failed to hash password", 500)
	}
	fmt.Printf("DEBUG changePassword: password hashed successfully\n")

	// Update password in auth service database
	if err := updatePasswordInAuthDB(pathUserID, hashedPassword); err != nil {
		fmt.Printf("DEBUG changePassword: failed to update password in auth DB, error = %v\n", err)
		return sendErrorResponse(h, "failed to update password", 500)
	}
	fmt.Printf("DEBUG changePassword: password updated successfully\n")

	response := map[string]string{"message": "password changed successfully"}
	return sendJSONResponse(h, response)
}

//export updatePreferences
func updatePreferences(e event.Event) uint32 {
	fmt.Printf("DEBUG updatePreferences: handler called\n")
	h, err := e.HTTP()
	if err != nil {
		fmt.Printf("DEBUG updatePreferences: failed to get HTTP event, error = %v\n", err)
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		fmt.Printf("DEBUG updatePreferences: OPTIONS request, returning 200\n")
		h.Return(200)
		return 0
	}

	fmt.Printf("DEBUG updatePreferences: HTTP method = %s\n", method)

	// Authenticate
	tokenUserID, retCode := authenticate(h)
	if retCode != 0 {
		fmt.Printf("DEBUG updatePreferences: authentication failed, retCode = %d\n", retCode)
		return retCode
	}
	fmt.Printf("DEBUG updatePreferences: authenticated userID = %s\n", tokenUserID)

	// Extract user ID from query parameters
	pathUserID, err := extractQueryParam(h, "id")
	if err != nil {
		fmt.Printf("DEBUG updatePreferences: extractQueryParam error = %v\n", err)
		debugMsg := fmt.Sprintf("missing or invalid 'id' query parameter. Error: %v", err)
		return sendErrorResponse(h, debugMsg, 400)
	}
	fmt.Printf("DEBUG updatePreferences: extracted pathUserID = %s\n", pathUserID)

	// Verify user can only update their own preferences
	if tokenUserID != pathUserID {
		fmt.Printf("DEBUG updatePreferences: authorization failed - tokenUserID=%s, pathUserID=%s\n", tokenUserID, pathUserID)
		return sendErrorResponse(h, "unauthorized: can only update your own preferences", 403)
	}

	// Decode request body
	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req UpdatePreferencesRequest
	if err := reqDec.Decode(&req); err != nil {
		fmt.Printf("DEBUG updatePreferences: failed to decode request body, error = %v\n", err)
		return sendErrorResponse(h, "invalid request format", 400)
	}
	fmt.Printf("DEBUG updatePreferences: decoded request - Language=%s, DisplayMode=%s, Notifications=%v\n", req.Language, req.DisplayMode, req.Notifications)

	// Get existing profile or create default
	profile, err := getUserProfileFromDB(pathUserID)
	if err != nil {
		fmt.Printf("DEBUG updatePreferences: profile not found, creating default. Error: %v\n", err)
		profile = createDefaultProfile(pathUserID, "", "")
	} else {
		fmt.Printf("DEBUG updatePreferences: found existing profile\n")
	}

	// Update preferences if provided
	if req.Language != "" {
		profile.Preferences.Language = strings.TrimSpace(req.Language)
		fmt.Printf("DEBUG updatePreferences: updated Language = %s\n", profile.Preferences.Language)
	}
	if req.Notifications != nil {
		profile.Preferences.Notifications = req.Notifications
		fmt.Printf("DEBUG updatePreferences: updated Notifications = %v\n", *profile.Preferences.Notifications)
	}
	if req.DisplayMode != "" {
		displayMode := strings.TrimSpace(strings.ToLower(req.DisplayMode))
		if displayMode != "light" && displayMode != "dark" {
			fmt.Printf("DEBUG updatePreferences: invalid displayMode = %s\n", displayMode)
			return sendErrorResponse(h, "displayMode must be 'light' or 'dark'", 400)
		}
		profile.Preferences.DisplayMode = displayMode
		fmt.Printf("DEBUG updatePreferences: updated DisplayMode = %s\n", profile.Preferences.DisplayMode)
	}

	// Save updated profile
	if err := saveUserProfile(*profile); err != nil {
		fmt.Printf("DEBUG updatePreferences: failed to save profile, error = %v\n", err)
		return sendErrorResponse(h, "failed to update preferences", 500)
	}
	fmt.Printf("DEBUG updatePreferences: preferences saved successfully\n")

	return sendJSONResponse(h, profile)
}

