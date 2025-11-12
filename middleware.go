package lib

import (
	"encoding/json"
	"fmt"

	http "github.com/taubyte/go-sdk/http/event"
)

// HandlerFunc represents a handler function that processes authenticated requests
type HandlerFunc func(h http.Event, userID string) (interface{}, error)

// handleRequest wraps a handler with common middleware (CORS, OPTIONS, auth, authorization)
func handleRequest(h http.Event, handler HandlerFunc, requireUserIDMatch bool) uint32 {
	// Set CORS headers
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	// Authenticate user
	tokenUserID, retCode := authenticate(h)
	if retCode != 0 {
		return retCode
	}

	// Extract user ID from query parameters if required
	var pathUserID string
	if requireUserIDMatch {
		var err error
		pathUserID, err = extractQueryParam(h, "id")
		if err != nil {
			return sendErrorResponse(h, fmt.Sprintf("missing or invalid 'id' query parameter: %v", err), 400)
		}

		// Verify user can only access their own resources
		if tokenUserID != pathUserID {
			return sendErrorResponse(h, "unauthorized: can only access your own resources", 403)
		}
	} else {
		pathUserID = tokenUserID
	}

	// Call the actual handler
	result, err := handler(h, pathUserID)
	if err != nil {
		// Check if it's a known error type
		if httpErr, ok := err.(*HTTPError); ok {
			return sendErrorResponse(h, httpErr.Message, httpErr.Code)
		}
		// Default to 500 for unknown errors
		return sendErrorResponse(h, fmt.Sprintf("internal server error: %v", err), 500)
	}

	// Send success response
	return sendJSONResponse(h, result)
}

// HTTPError represents an HTTP error with status code
type HTTPError struct {
	Message string
	Code    int
}

func (e *HTTPError) Error() string {
	return e.Message
}

// NewHTTPError creates a new HTTP error
func NewHTTPError(message string, code int) *HTTPError {
	return &HTTPError{Message: message, Code: code}
}

// decodeRequestBody decodes JSON request body into the provided struct
func decodeRequestBody(h http.Event, v interface{}) error {
	decoder := json.NewDecoder(h.Body())
	defer h.Body().Close()
	
	if err := decoder.Decode(v); err != nil {
		return NewHTTPError("invalid request format", 400)
	}
	return nil
}

