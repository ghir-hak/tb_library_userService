package lib

import (
	"testing"
)

func TestValidateUpdateProfileRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     UpdateProfileRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: UpdateProfileRequest{
				Name:  "John Doe",
				Email: "john@example.com",
				Phone: "1234567890",
			},
			wantErr: false,
		},
		{
			name: "empty name",
			req: UpdateProfileRequest{
				Name:  "   ",
				Email: "john@example.com",
			},
			wantErr: true,
		},
		{
			name: "invalid email",
			req: UpdateProfileRequest{
				Name:  "John Doe",
				Email: "invalid-email",
			},
			wantErr: true,
		},
		{
			name: "empty email whitespace",
			req: UpdateProfileRequest{
				Name:  "John Doe",
				Email: "   ",
			},
			wantErr: true,
		},
		{
			name: "valid partial update",
			req: UpdateProfileRequest{
				Name: "John Doe",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUpdateProfileRequest(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUpdateProfileRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateChangePasswordRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     ChangePasswordRequest
		wantErr bool
	}{
		{
			name: "valid password",
			req: ChangePasswordRequest{
				NewPassword: "newpassword123",
			},
			wantErr: false,
		},
		{
			name: "empty password",
			req: ChangePasswordRequest{
				NewPassword: "",
			},
			wantErr: true,
		},
		{
			name: "whitespace only password",
			req: ChangePasswordRequest{
				NewPassword: "   ",
			},
			wantErr: true,
		},
		{
			name: "password too short",
			req: ChangePasswordRequest{
				NewPassword: "12345",
			},
			wantErr: true,
		},
		{
			name: "minimum length password",
			req: ChangePasswordRequest{
				NewPassword: "123456",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChangePasswordRequest(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateChangePasswordRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateUpdatePreferencesRequest(t *testing.T) {
	notificationsTrue := true
	notificationsFalse := false

	tests := []struct {
		name    string
		req     UpdatePreferencesRequest
		wantErr bool
	}{
		{
			name: "valid light mode",
			req: UpdatePreferencesRequest{
				DisplayMode: "light",
			},
			wantErr: false,
		},
		{
			name: "valid dark mode",
			req: UpdatePreferencesRequest{
				DisplayMode: "dark",
			},
			wantErr: false,
		},
		{
			name: "invalid display mode",
			req: UpdatePreferencesRequest{
				DisplayMode: "invalid",
			},
			wantErr: true,
		},
		{
			name: "uppercase display mode",
			req: UpdatePreferencesRequest{
				DisplayMode: "LIGHT",
			},
			wantErr: false, // Should be converted to lowercase
		},
		{
			name: "valid with notifications",
			req: UpdatePreferencesRequest{
				DisplayMode:  "dark",
				Notifications: &notificationsTrue,
			},
			wantErr: false,
		},
		{
			name: "empty display mode",
			req: UpdatePreferencesRequest{
				Notifications: &notificationsFalse,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUpdatePreferencesRequest(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUpdatePreferencesRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

