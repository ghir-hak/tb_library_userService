package lib

// UserProfile represents a user profile in the system
type UserProfile struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Email       string      `json:"email"`
	Phone       string      `json:"phone"`
	Address     string      `json:"address,omitempty"`
	Preferences Preferences `json:"preferences"`
	Roles       []string    `json:"roles"`
}

// Preferences represents user preferences
type Preferences struct {
	Language     string `json:"language,omitempty"`
	Notifications *bool  `json:"notifications,omitempty"`
	DisplayMode  string `json:"displayMode,omitempty"` // "light" or "dark"
}

// UpdateProfileRequest represents the request body for updating user profile
type UpdateProfileRequest struct {
	Name    string `json:"name,omitempty"`
	Email   string `json:"email,omitempty"`
	Phone   string `json:"phone,omitempty"`
	Address string `json:"address,omitempty"`
}

// ChangePasswordRequest represents the request body for changing password
type ChangePasswordRequest struct {
	NewPassword string `json:"newPassword"`
}

// UpdatePreferencesRequest represents the request body for updating preferences
type UpdatePreferencesRequest struct {
	Language     string `json:"language,omitempty"`
	Notifications *bool  `json:"notifications,omitempty"`
	DisplayMode  string `json:"displayMode,omitempty"`
}

