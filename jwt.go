package lib

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtSecret = "your-secret-key-change-in-production"
)

// Claims represents JWT claims
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// ValidateToken validates a JWT token and returns the user ID
func ValidateToken(tokenString string) (string, error) {
	fmt.Printf("DEBUG ValidateToken: validating token (length = %d)\n", len(tokenString))
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		fmt.Printf("DEBUG ValidateToken: parsing token, method = %v\n", token.Method)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			fmt.Printf("DEBUG ValidateToken: invalid signing method\n")
			return nil, errors.New("invalid signing method")
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		fmt.Printf("DEBUG ValidateToken: token parsing failed, error = %v\n", err)
		return "", err
	}

	if !token.Valid {
		fmt.Printf("DEBUG ValidateToken: token is not valid\n")
		return "", errors.New("invalid token")
	}

	fmt.Printf("DEBUG ValidateToken: token validated successfully, userID = %s\n", claims.UserID)
	return claims.UserID, nil
}

