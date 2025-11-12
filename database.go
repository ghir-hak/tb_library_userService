package lib

import (
	"encoding/json"
	"fmt"

	"github.com/taubyte/go-sdk/database"
)

const (
	userProfilesPrefix = "/users/profiles/"
	userIDPrefix       = "/users/id/"
	userUsernamePrefix = "/users/"
)

// getUserProfileFromDB retrieves a user profile by ID from the database
func getUserProfileFromDB(id string) (*UserProfile, error) {
	db, err := database.New("/data")
	if err != nil {
		return nil, fmt.Errorf("db connection failed: %w", err)
	}

	key := fmt.Sprintf("%s%s", userProfilesPrefix, id)
	data, err := db.Get(key)
	if err != nil {
		return nil, fmt.Errorf("user profile not found for ID '%s': %w", id, err)
	}

	var profile UserProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user profile: %w", err)
	}

	return &profile, nil
}

// saveUserProfile saves a user profile to the database
func saveUserProfile(profile UserProfile) error {
	db, err := database.New("/data")
	if err != nil {
		return fmt.Errorf("db connection failed: %w", err)
	}

	profileData, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to marshal user profile: %w", err)
	}

	key := fmt.Sprintf("%s%s", userProfilesPrefix, profile.ID)
	if err := db.Put(key, profileData); err != nil {
		return fmt.Errorf("failed to save user profile: %w", err)
	}

	return nil
}

// createDefaultProfile creates a default user profile with sensible defaults
func createDefaultProfile(userID, name, email string) *UserProfile {
	notifications := true
	return &UserProfile{
		ID:      userID,
		Name:    name,
		Email:   email,
		Phone:   "",
		Address: "",
		Preferences: Preferences{
			Language:      "en",
			Notifications: &notifications,
			DisplayMode:   "light",
		},
		Roles: []string{"buyer"},
	}
}

// updatePasswordInAuthDB updates the password in the auth service's database
func updatePasswordInAuthDB(userID, hashedPassword string) error {
	db, err := database.New("/data")
	if err != nil {
		return fmt.Errorf("db connection failed: %w", err)
	}

	// Get user by ID to find username
	idKey := fmt.Sprintf("%s%s", userIDPrefix, userID)
	userData, err := db.Get(idKey)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse the user data
	var userDataMap map[string]interface{}
	if err := json.Unmarshal(userData, &userDataMap); err != nil {
		return fmt.Errorf("failed to unmarshal user data: %w", err)
	}

	username, ok := userDataMap["username"].(string)
	if !ok || username == "" {
		return fmt.Errorf("invalid user data: username not found")
	}

	// Update password in the user data
	userDataMap["password"] = hashedPassword

	// Serialize updated user data
	updatedUserData, err := json.Marshal(userDataMap)
	if err != nil {
		return fmt.Errorf("failed to marshal user data: %w", err)
	}

	// Update by ID
	if err := db.Put(idKey, updatedUserData); err != nil {
		return fmt.Errorf("failed to update user by ID: %w", err)
	}

	// Update by username
	usernameKey := fmt.Sprintf("%s%s", userUsernamePrefix, username)
	if err := db.Put(usernameKey, updatedUserData); err != nil {
		return fmt.Errorf("failed to update user by username: %w", err)
	}

	return nil
}

