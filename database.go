package lib

import (
	"encoding/json"
	"fmt"

	"github.com/taubyte/go-sdk/database"
)

const (
	userProfilesPrefix = "/users/profiles/"
)

// getUserProfileFromDB retrieves a user profile by ID from the database
func getUserProfileFromDB(id string) (*UserProfile, error) {
	fmt.Printf("DEBUG getUserProfileFromDB: looking up profile for id = %s\n", id)
	db, err := database.New("/data")
	if err != nil {
		fmt.Printf("DEBUG getUserProfileFromDB: db connection failed, error = %v\n", err)
		return nil, fmt.Errorf("db connection failed: %w", err)
	}

	key := fmt.Sprintf("%s%s", userProfilesPrefix, id)
	fmt.Printf("DEBUG getUserProfileFromDB: database key = %s\n", key)

	data, err := db.Get(key)
	if err != nil {
		fmt.Printf("DEBUG getUserProfileFromDB: profile not found for key %s, error = %v\n", key, err)
		return nil, fmt.Errorf("user profile not found for ID '%s': %w", id, err)
	}

	fmt.Printf("DEBUG getUserProfileFromDB: retrieved data length = %d bytes\n", len(data))

	var profile UserProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		fmt.Printf("DEBUG getUserProfileFromDB: failed to unmarshal, error = %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal user profile: %w", err)
	}

	fmt.Printf("DEBUG getUserProfileFromDB: successfully retrieved profile for id = %s\n", id)
	return &profile, nil
}

// saveUserProfile saves a user profile to the database
func saveUserProfile(profile UserProfile) error {
	fmt.Printf("DEBUG saveUserProfile: saving profile for id = %s\n", profile.ID)
	db, err := database.New("/data")
	if err != nil {
		fmt.Printf("DEBUG saveUserProfile: db connection failed, error = %v\n", err)
		return fmt.Errorf("db connection failed: %w", err)
	}

	// Serialize profile
	profileData, err := json.Marshal(profile)
	if err != nil {
		fmt.Printf("DEBUG saveUserProfile: failed to marshal profile, error = %v\n", err)
		return fmt.Errorf("failed to marshal user profile: %w", err)
	}
	fmt.Printf("DEBUG saveUserProfile: marshaled profile data length = %d bytes\n", len(profileData))

	// Store by user ID
	key := fmt.Sprintf("%s%s", userProfilesPrefix, profile.ID)
	fmt.Printf("DEBUG saveUserProfile: saving to database key = %s\n", key)

	if err := db.Put(key, profileData); err != nil {
		fmt.Printf("DEBUG saveUserProfile: failed to save to database, error = %v\n", err)
		return fmt.Errorf("failed to save user profile: %w", err)
	}

	fmt.Printf("DEBUG saveUserProfile: successfully saved profile for id = %s\n", profile.ID)
	return nil
}

// createDefaultProfile creates a default user profile with sensible defaults
func createDefaultProfile(userID, name, email string) *UserProfile {
	fmt.Printf("DEBUG createDefaultProfile: creating default profile for userID = %s, name = %s, email = %s\n", userID, name, email)
	notifications := true
	profile := &UserProfile{
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
	fmt.Printf("DEBUG createDefaultProfile: created default profile\n")
	return profile
}

// updatePasswordInAuthDB updates the password in the auth service's database
func updatePasswordInAuthDB(userID, hashedPassword string) error {
	fmt.Printf("DEBUG updatePasswordInAuthDB: updating password for userID = %s\n", userID)
	db, err := database.New("/data")
	if err != nil {
		fmt.Printf("DEBUG updatePasswordInAuthDB: db connection failed, error = %v\n", err)
		return fmt.Errorf("db connection failed: %w", err)
	}

	// Get user by ID to find username
	idKey := fmt.Sprintf("/users/id/%s", userID)
	fmt.Printf("DEBUG updatePasswordInAuthDB: looking up user at key = %s\n", idKey)

	userData, err := db.Get(idKey)
	if err != nil {
		fmt.Printf("DEBUG updatePasswordInAuthDB: user not found at key %s, error = %v\n", idKey, err)
		return fmt.Errorf("user not found: %w", err)
	}

	fmt.Printf("DEBUG updatePasswordInAuthDB: retrieved user data length = %d bytes\n", len(userData))

	// Parse the user data
	var userDataMap map[string]interface{}
	if err := json.Unmarshal(userData, &userDataMap); err != nil {
		fmt.Printf("DEBUG updatePasswordInAuthDB: failed to unmarshal user data, error = %v\n", err)
		return fmt.Errorf("failed to unmarshal user data: %w", err)
	}

	username, ok := userDataMap["username"].(string)
	if !ok || username == "" {
		fmt.Printf("DEBUG updatePasswordInAuthDB: username not found in user data\n")
		return fmt.Errorf("invalid user data: username not found")
	}
	fmt.Printf("DEBUG updatePasswordInAuthDB: found username = %s\n", username)

	// Update password in the user data
	userDataMap["password"] = hashedPassword
	fmt.Printf("DEBUG updatePasswordInAuthDB: updated password in user data map\n")

	// Serialize updated user data
	updatedUserData, err := json.Marshal(userDataMap)
	if err != nil {
		fmt.Printf("DEBUG updatePasswordInAuthDB: failed to marshal updated user data, error = %v\n", err)
		return fmt.Errorf("failed to marshal user data: %w", err)
	}

	// Update by ID
	fmt.Printf("DEBUG updatePasswordInAuthDB: updating user at key = %s\n", idKey)
	if err := db.Put(idKey, updatedUserData); err != nil {
		fmt.Printf("DEBUG updatePasswordInAuthDB: failed to update user by ID, error = %v\n", err)
		return fmt.Errorf("failed to update user by ID: %w", err)
	}

	// Update by username
	usernameKey := fmt.Sprintf("/users/%s", username)
	fmt.Printf("DEBUG updatePasswordInAuthDB: updating user at key = %s\n", usernameKey)
	if err := db.Put(usernameKey, updatedUserData); err != nil {
		fmt.Printf("DEBUG updatePasswordInAuthDB: failed to update user by username, error = %v\n", err)
		return fmt.Errorf("failed to update user by username: %w", err)
	}

	fmt.Printf("DEBUG updatePasswordInAuthDB: successfully updated password for userID = %s\n", userID)
	return nil
}

