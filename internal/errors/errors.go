package errors

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// AppError represents a structured application error
type AppError struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Message    string            `json:"message"`
	Details    string            `json:"details,omitempty"`
	StatusCode int               `json:"status_code"`
	Timestamp  time.Time         `json:"timestamp"`
	Context    map[string]string `json:"context,omitempty"`
	Cause      error             `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Type, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// WithContext adds contextual information to the error
func (e *AppError) WithContext(key, value string) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]string)
	}
	e.Context[key] = value
	return e
}

// ToResponse converts the error to a JSON response format
func (e *AppError) ToResponse() map[string]interface{} {
	response := map[string]interface{}{
		"error": map[string]interface{}{
			"id":        e.ID,
			"type":      e.Type,
			"message":   e.Message,
			"timestamp": e.Timestamp,
		},
	}

	if e.Details != "" {
		response["error"].(map[string]interface{})["details"] = e.Details
	}

	if len(e.Context) > 0 {
		response["error"].(map[string]interface{})["context"] = e.Context
	}

	return response
}

// NewValidationError creates a new validation error
func NewValidationError(message, details string) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "validation_error",
		Message:    message,
		Details:    details,
		StatusCode: http.StatusBadRequest,
		Timestamp:  time.Now(),
		Context:    make(map[string]string),
	}
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(resource, id string) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "not_found_error",
		Message:    fmt.Sprintf("%s not found", resource),
		Details:    fmt.Sprintf("Resource '%s' with ID '%s' does not exist", resource, id),
		StatusCode: http.StatusNotFound,
		Timestamp:  time.Now(),
		Context:    map[string]string{"resource": resource, "resource_id": id},
	}
}

// NewDatabaseError creates a new database error
func NewDatabaseError(operation string, cause error) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "database_error",
		Message:    "Database operation failed",
		Details:    fmt.Sprintf("Operation '%s' failed", operation),
		StatusCode: http.StatusInternalServerError,
		Timestamp:  time.Now(),
		Context:    map[string]string{"operation": operation},
		Cause:      cause,
	}
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(message string) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "authentication_error",
		Message:    message,
		Details:    "Authentication credentials are invalid or missing",
		StatusCode: http.StatusUnauthorized,
		Timestamp:  time.Now(),
		Context:    make(map[string]string),
	}
}

// NewAuthorizationError creates a new authorization error
func NewAuthorizationError(resource, action string) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "authorization_error",
		Message:    "Insufficient permissions",
		Details:    fmt.Sprintf("User not authorized to %s %s", action, resource),
		StatusCode: http.StatusForbidden,
		Timestamp:  time.Now(),
		Context:    map[string]string{"resource": resource, "action": action},
	}
}

// NewRateLimitError creates a new rate limit error
func NewRateLimitError(retryAfter int) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "rate_limit_error",
		Message:    "Rate limit exceeded",
		Details:    fmt.Sprintf("Too many requests. Retry after %d seconds", retryAfter),
		StatusCode: http.StatusTooManyRequests,
		Timestamp:  time.Now(),
		Context:    map[string]string{"retry_after": fmt.Sprintf("%d", retryAfter)},
	}
}

// NewInternalError creates a new internal server error
func NewInternalError(component string, cause error) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "internal_error",
		Message:    "Internal server error",
		Details:    fmt.Sprintf("Error in component '%s'", component),
		StatusCode: http.StatusInternalServerError,
		Timestamp:  time.Now(),
		Context:    map[string]string{"component": component},
		Cause:      cause,
	}
}

// NewServiceUnavailableError creates a new service unavailable error
func NewServiceUnavailableError(service string) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "service_unavailable_error",
		Message:    "Service temporarily unavailable",
		Details:    fmt.Sprintf("Service '%s' is currently unavailable", service),
		StatusCode: http.StatusServiceUnavailable,
		Timestamp:  time.Now(),
		Context:    map[string]string{"service": service},
	}
}

// NewConflictError creates a new conflict error
func NewConflictError(resource, reason string) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "conflict_error",
		Message:    "Resource conflict",
		Details:    fmt.Sprintf("Conflict with resource '%s': %s", resource, reason),
		StatusCode: http.StatusConflict,
		Timestamp:  time.Now(),
		Context:    map[string]string{"resource": resource, "reason": reason},
	}
}

// NewTimeoutError creates a new timeout error
func NewTimeoutError(operation string, timeout time.Duration) *AppError {
	return &AppError{
		ID:         uuid.New().String(),
		Type:       "timeout_error",
		Message:    "Operation timeout",
		Details:    fmt.Sprintf("Operation '%s' timed out after %v", operation, timeout),
		StatusCode: http.StatusRequestTimeout,
		Timestamp:  time.Now(),
		Context:    map[string]string{"operation": operation, "timeout": timeout.String()},
	}
}

// Error types for categorization
const (
	ErrorTypeValidation      = "validation_error"
	ErrorTypeNotFound        = "not_found_error"
	ErrorTypeDatabase        = "database_error"
	ErrorTypeAuthentication  = "authentication_error"
	ErrorTypeAuthorization   = "authorization_error"
	ErrorTypeRateLimit       = "rate_limit_error"
	ErrorTypeInternal        = "internal_error"
	ErrorTypeServiceUnavail  = "service_unavailable_error"
	ErrorTypeConflict        = "conflict_error"
	ErrorTypeTimeout         = "timeout_error"
)

// ValidationResult represents the result of input validation
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors"`
}

// ValidationError represents a single validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

// ErrorHandler middleware for centralized error handling
func ErrorHandler() func(c interface{}, err error) {
	return func(c interface{}, err error) {
		// This would be implemented to handle different error types
		// and respond with appropriate HTTP status codes and messages
	}
}

// RecoveryHandler handles panics and converts them to internal errors
func RecoveryHandler() func(c interface{}, err interface{}) {
	return func(c interface{}, err interface{}) {
		// Convert panic to internal error
		// Log the error and stack trace
		// Return appropriate error response
	}
}