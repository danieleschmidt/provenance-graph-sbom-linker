package errors

import (
	"fmt"
	"net/http"
	"runtime"
)

// ErrorCode represents different types of errors
type ErrorCode string

const (
	// General errors
	ErrCodeInternal      ErrorCode = "INTERNAL_ERROR"
	ErrCodeInvalidInput  ErrorCode = "INVALID_INPUT"
	ErrCodeNotFound      ErrorCode = "NOT_FOUND"
	ErrCodeUnauthorized  ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden     ErrorCode = "FORBIDDEN"
	ErrCodeConflict      ErrorCode = "CONFLICT"
	ErrCodeTimeout       ErrorCode = "TIMEOUT"

	// Validation errors
	ErrCodeValidation       ErrorCode = "VALIDATION_ERROR"
	ErrCodeMaliciousContent ErrorCode = "MALICIOUS_CONTENT"
	ErrCodeUnsafeOperation  ErrorCode = "UNSAFE_OPERATION"

	// Database errors
	ErrCodeDatabaseConnection ErrorCode = "DATABASE_CONNECTION"
	ErrCodeDatabaseQuery      ErrorCode = "DATABASE_QUERY"
	ErrCodeDatabaseConstraint ErrorCode = "DATABASE_CONSTRAINT"

	// External service errors
	ErrCodeExternalService ErrorCode = "EXTERNAL_SERVICE"
	ErrCodeNetworkError    ErrorCode = "NETWORK_ERROR"

	// Authentication/Authorization errors
	ErrCodeInvalidToken   ErrorCode = "INVALID_TOKEN"
	ErrCodeExpiredToken   ErrorCode = "EXPIRED_TOKEN"
	ErrCodeInsufficientPermissions ErrorCode = "INSUFFICIENT_PERMISSIONS"

	// Business logic errors
	ErrCodeInvalidArtifact     ErrorCode = "INVALID_ARTIFACT"
	ErrCodeInvalidSBOM         ErrorCode = "INVALID_SBOM"
	ErrCodeInvalidProvenance   ErrorCode = "INVALID_PROVENANCE"
	ErrCodeSignatureVerification ErrorCode = "SIGNATURE_VERIFICATION"
)

// AppError represents a structured application error
type AppError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	StatusCode int                    `json:"-"`
	Internal   error                  `json:"-"`
	Context    map[string]interface{} `json:"context,omitempty"`
}

func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Internal
}

func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// Error constructors
func NewInternalError(message string, err error) *AppError {
	return &AppError{
		Code:       ErrCodeInternal,
		Message:    message,
		StatusCode: http.StatusInternalServerError,
		Internal:   err,
	}
}

func NewValidationError(message string, details string) *AppError {
	return &AppError{
		Code:       ErrCodeValidation,
		Message:    message,
		Details:    details,
		StatusCode: http.StatusBadRequest,
	}
}

func NewNotFoundError(resource string, id string) *AppError {
	return &AppError{
		Code:       ErrCodeNotFound,
		Message:    fmt.Sprintf("%s not found", resource),
		Details:    fmt.Sprintf("ID: %s", id),
		StatusCode: http.StatusNotFound,
	}
}

func NewUnauthorizedError(message string) *AppError {
	return &AppError{
		Code:       ErrCodeUnauthorized,
		Message:    message,
		StatusCode: http.StatusUnauthorized,
	}
}

func NewForbiddenError(message string) *AppError {
	return &AppError{
		Code:       ErrCodeForbidden,
		Message:    message,
		StatusCode: http.StatusForbidden,
	}
}

func NewConflictError(message string, details string) *AppError {
	return &AppError{
		Code:       ErrCodeConflict,
		Message:    message,
		Details:    details,
		StatusCode: http.StatusConflict,
	}
}

func NewDatabaseError(operation string, err error) *AppError {
	return &AppError{
		Code:       ErrCodeDatabaseQuery,
		Message:    fmt.Sprintf("Database operation failed: %s", operation),
		StatusCode: http.StatusInternalServerError,
		Internal:   err,
	}
}

func NewExternalServiceError(service string, err error) *AppError {
	return &AppError{
		Code:       ErrCodeExternalService,
		Message:    fmt.Sprintf("External service error: %s", service),
		StatusCode: http.StatusBadGateway,
		Internal:   err,
	}
}

func NewMaliciousContentError(field string) *AppError {
	return &AppError{
		Code:       ErrCodeMaliciousContent,
		Message:    "Potentially malicious content detected",
		Details:    fmt.Sprintf("Field: %s", field),
		StatusCode: http.StatusBadRequest,
	}
}

func NewSignatureVerificationError(reason string) *AppError {
	return &AppError{
		Code:       ErrCodeSignatureVerification,
		Message:    "Signature verification failed",
		Details:    reason,
		StatusCode: http.StatusUnprocessableEntity,
	}
}

// IsErrorCode checks if an error matches a specific error code
func IsErrorCode(err error, code ErrorCode) bool {
	appErr, ok := err.(*AppError)
	if !ok {
		return false
	}
	return appErr.Code == code
}

// GetErrorCode returns the error code from an error, or empty string if not an AppError
func GetErrorCode(err error) ErrorCode {
	appErr, ok := err.(*AppError)
	if !ok {
		return ""
	}
	return appErr.Code
}

// GetStatusCode returns the HTTP status code for an error
func GetStatusCode(err error) int {
	appErr, ok := err.(*AppError)
	if !ok {
		return http.StatusInternalServerError
	}
	return appErr.StatusCode
}

// ErrorResponse represents the JSON error response format
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    ErrorCode              `json:"code"`
	Message string                 `json:"message"`
	Details string                 `json:"details,omitempty"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// ToResponse converts an AppError to an ErrorResponse
func (e *AppError) ToResponse() ErrorResponse {
	return ErrorResponse{
		Error: ErrorDetail{
			Code:    e.Code,
			Message: e.Message,
			Details: e.Details,
			Context: e.Context,
		},
	}
}

// FromError converts any error to an AppError
func FromError(err error) *AppError {
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}
	
	return NewInternalError("An unexpected error occurred", err)
}

// Chain multiple errors together
type ErrorChain struct {
	errors []*AppError
}

func NewErrorChain() *ErrorChain {
	return &ErrorChain{
		errors: make([]*AppError, 0),
	}
}

func (ec *ErrorChain) Add(err *AppError) *ErrorChain {
	ec.errors = append(ec.errors, err)
	return ec
}

func (ec *ErrorChain) HasErrors() bool {
	return len(ec.errors) > 0
}

func (ec *ErrorChain) Errors() []*AppError {
	return ec.errors
}

func (ec *ErrorChain) First() *AppError {
	if len(ec.errors) == 0 {
		return nil
	}
	return ec.errors[0]
}

func (ec *ErrorChain) ToResponse() interface{} {
	if len(ec.errors) == 1 {
		return ec.errors[0].ToResponse()
	}
	
	responses := make([]ErrorResponse, len(ec.errors))
	for i, err := range ec.errors {
		responses[i] = err.ToResponse()
	}
	
	return map[string]interface{}{
		"errors": responses,
	}
}

// Utility function for stack trace (used in enhanced error handling)
func getStackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	
	var stack string
	for {
		frame, more := frames.Next()
		stack += fmt.Sprintf("%s:%d %s\n", frame.File, frame.Line, frame.Function)
		if !more {
			break
		}
	}
	return stack
}