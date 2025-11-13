package lib

import (
	"encoding/json"
	"fmt"

	"github.com/taubyte/go-sdk/database"
)

// getUserProfileFromDB retrieves a user profile by ID from the database
func getUserProfileFromDB(id string) (*UserProfile, error) {
	db, err := database.New("/data")
	if err != nil {
		return nil, err
	}

	data, err := db.Get(fmt.Sprintf("/users/profiles/%s", id))
	if err != nil {
		return nil, err
	}

	var profile UserProfile
	return &profile, json.Unmarshal(data, &profile)
}

// saveUserProfile saves a user profile to the database
func saveUserProfile(profile UserProfile) error {
	db, err := database.New("/data")
	if err != nil {
		return err
	}

	data, err := json.Marshal(profile)
	if err != nil {
		return err
	}

	return db.Put(fmt.Sprintf("/users/profiles/%s", profile.ID), data)
}

// updatePasswordInAuthDB updates the password in the auth service's database
func updatePasswordInAuthDB(userID, hashedPassword string) error {
	db, err := database.New("/usersdata")
	if err != nil {
		return err
	}

	userData, err := db.Get(fmt.Sprintf("/users/id/%s", userID))
	if err != nil {
		return err
	}

	var userDataMap map[string]interface{}
	if err := json.Unmarshal(userData, &userDataMap); err != nil {
		return err
	}

	username, _ := userDataMap["username"].(string)
	userDataMap["password"] = hashedPassword

	updatedData, err := json.Marshal(userDataMap)
	if err != nil {
		return err
	}

	if err := db.Put(fmt.Sprintf("/users/id/%s", userID), updatedData); err != nil {
		return err
	}

	return db.Put(fmt.Sprintf("/users/%s", username), updatedData)
}
