package lib

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	http "github.com/taubyte/go-sdk/http/event"
	"golang.org/x/crypto/bcrypt"
)

// setCORSHeaders sets CORS headers for HTTP responses
func setCORSHeaders(h http.Event) {
	h.Headers().Set("Access-Control-Allow-Origin", "*")
	h.Headers().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	h.Headers().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

// sendJSONResponse sends a JSON response with status 200
func sendJSONResponse(h http.Event, data interface{}) uint32 {
	fmt.Printf("DEBUG sendJSONResponse: marshaling response data\n")
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("DEBUG sendJSONResponse: failed to marshal, error = %v\n", err)
		return handleHTTPError(h, err, 500)
	}
	fmt.Printf("DEBUG sendJSONResponse: sending response (length = %d bytes)\n", len(jsonData))
	h.Headers().Set("Content-Type", "application/json")
	h.Write(jsonData)
	h.Return(200)
	return 0
}

// handleHTTPError handles HTTP errors and sends error response
func handleHTTPError(h http.Event, err error, code int) uint32 {
	h.Write([]byte(err.Error()))
	h.Return(code)
	return 1
}

// sendErrorResponse sends a JSON error response
func sendErrorResponse(h http.Event, message string, code int) uint32 {
	fmt.Printf("DEBUG sendErrorResponse: sending error response - code = %d, message = %s\n", code, message)
	response := map[string]string{"error": message}
	jsonData, err := json.Marshal(response)
	if err != nil {
		fmt.Printf("DEBUG sendErrorResponse: failed to marshal error response, error = %v\n", err)
		h.Write([]byte("Internal server error"))
		h.Return(500)
		return 1
	}
	h.Headers().Set("Content-Type", "application/json")
	h.Write(jsonData)
	h.Return(code)
	return 1
}

// hashPassword hashes a password using bcrypt
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// comparePassword compares a password with a hash
func comparePassword(hashedPassword, password string) bool {
	// Trim whitespace from hash to handle any encoding/storage issues
	hashedPassword = strings.TrimSpace(hashedPassword)

	// Validate inputs
	if len(hashedPassword) == 0 || len(password) == 0 {
		return false
	}

	// Validate hash prefix (bcrypt hashes start with $2a$, $2b$, or $2y$)
	if !strings.HasPrefix(hashedPassword, "$2a$") &&
		!strings.HasPrefix(hashedPassword, "$2b$") &&
		!strings.HasPrefix(hashedPassword, "$2y$") {
		return false
	}

	// Compare using bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// authenticate extracts and validates JWT token from Authorization header
func authenticate(h http.Event) (string, uint32) {
	authHeader, err := h.Headers().Get("Authorization")
	if err != nil || authHeader == "" {
		return "", sendErrorResponse(h, "missing authorization header", 401)
	}

	// Extract token from "Bearer <token>"
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return "", sendErrorResponse(h, "invalid authorization format", 401)
	}

	tokenString := authHeader[7:]
	
	userID, err := ValidateToken(tokenString)
	if err != nil {
		// Include the actual error message in the response for debugging
		errorMsg := fmt.Sprintf("invalid or expired token - validation error: %v", err)
		return "", sendErrorResponse(h, errorMsg, 401)
	}

	return userID, 0
}

// extractQueryParam extracts the user ID from query parameters
// Handles URLs like: /api/users?id=123, /api/users?id=123&action=password
func extractQueryParam(h http.Event, paramName string) (string, error) {
	path, err := h.Path()
	if err != nil {
		return "", fmt.Errorf("failed to get path: %w", err)
	}

	// DEBUG: Print what Path() returns
	fmt.Printf("DEBUG extractQueryParam: path = '%s'\n", path)
	fmt.Printf("DEBUG extractQueryParam: looking for param '%s'\n", paramName)

	// Split path to get query string
	parts := strings.SplitN(path, "?", 2)
	fmt.Printf("DEBUG extractQueryParam: split parts count = %d\n", len(parts))
	if len(parts) > 0 {
		fmt.Printf("DEBUG extractQueryParam: parts[0] = '%s'\n", parts[0])
	}
	if len(parts) > 1 {
		fmt.Printf("DEBUG extractQueryParam: parts[1] (query string) = '%s'\n", parts[1])
	}

	if len(parts) < 2 {
		// Try to get more info about the request
		method, _ := h.Method()
		fmt.Printf("DEBUG extractQueryParam: HTTP method = '%s'\n", method)
		return "", fmt.Errorf("no query parameters found in path: '%s'", path)
	}

	// Parse query string using Go's standard library
	queryParams, err := url.ParseQuery(parts[1])
	if err != nil {
		fmt.Printf("DEBUG extractQueryParam: ParseQuery error = %v\n", err)
		return "", fmt.Errorf("failed to parse query string: %w", err)
	}

	fmt.Printf("DEBUG extractQueryParam: parsed query params = %+v\n", queryParams)

	// Get the parameter value
	value := queryParams.Get(paramName)
	fmt.Printf("DEBUG extractQueryParam: value for '%s' = '%s'\n", paramName, value)
	
	if value == "" {
		return "", fmt.Errorf("query parameter '%s' not found", paramName)
	}

	return strings.TrimSpace(value), nil
}

