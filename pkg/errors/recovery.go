package errors

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// RecoveryHandler handles panic recovery with structured logging
type RecoveryHandler struct {
	logger *logrus.Logger
}

// NewRecoveryHandler creates a new recovery handler
func NewRecoveryHandler(logger *logrus.Logger) *RecoveryHandler {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}
	return &RecoveryHandler{
		logger: logger,
	}
}

// GinRecoveryMiddleware provides Gin middleware for panic recovery
func (rh *RecoveryHandler) GinRecoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, recovered interface{}) {
		err := rh.handleRecovery(c.Request.Context(), recovered)
		
		// Log the recovery
		rh.logger.WithFields(logrus.Fields{
			"error":      err.Error(),
			"path":       c.Request.URL.Path,
			"method":     c.Request.Method,
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
			"request_id": c.GetString("request_id"),
		}).Error("Panic recovered")
		
		// Return error response
		c.JSON(500, gin.H{
			"error": map[string]interface{}{
				"code":      "INTERNAL_SERVER_ERROR",
				"message":   "Internal server error occurred",
				"timestamp": time.Now().UTC(),
				"request_id": c.GetString("request_id"),
			},
		})
	})
}

// HandleRecovery handles generic panic recovery
func (rh *RecoveryHandler) HandleRecovery(ctx context.Context, recovered interface{}) error {
	return rh.handleRecovery(ctx, recovered)
}

// handleRecovery processes the recovered panic and creates structured error
func (rh *RecoveryHandler) handleRecovery(ctx context.Context, recovered interface{}) error {
	// Get stack trace
	stack := make([]byte, 4096)
	length := runtime.Stack(stack, true)
	
	// Create recovery error
	recoveryErr := &RecoveryError{
		RecoveredValue: recovered,
		StackTrace:     string(stack[:length]),
		Timestamp:      time.Now().UTC(),
	}
	
	// Add context information if available
	if ctx != nil {
		if requestID := ctx.Value("request_id"); requestID != nil {
			recoveryErr.RequestID = requestID.(string)
		}
		if userID := ctx.Value("user_id"); userID != nil {
			recoveryErr.UserID = userID.(string)
		}
	}
	
	return recoveryErr
}

// RecoveryError represents a recovered panic with context
type RecoveryError struct {
	RecoveredValue interface{} `json:"recovered_value"`
	StackTrace     string      `json:"stack_trace"`
	Timestamp      time.Time   `json:"timestamp"`
	RequestID      string      `json:"request_id,omitempty"`
	UserID         string      `json:"user_id,omitempty"`
}

// Error implements the error interface
func (re *RecoveryError) Error() string {
	return fmt.Sprintf("panic recovered: %v", re.RecoveredValue)
}

// String provides a detailed string representation
func (re *RecoveryError) String() string {
	return fmt.Sprintf("RecoveryError{\n  Value: %v\n  Timestamp: %v\n  RequestID: %s\n  UserID: %s\n  Stack:\n%s\n}",
		re.RecoveredValue, re.Timestamp, re.RequestID, re.UserID, re.StackTrace)
}

// SafeExecute executes a function with panic recovery
func (rh *RecoveryHandler) SafeExecute(ctx context.Context, operation string, fn func() error) error {
	defer func() {
		if recovered := recover(); recovered != nil {
			err := rh.handleRecovery(ctx, recovered)
			rh.logger.WithFields(logrus.Fields{
				"operation": operation,
				"error":     err.Error(),
			}).Error("Panic recovered during safe execution")
		}
	}()
	
	return fn()
}

// SafeExecuteWithResult executes a function with panic recovery and returns a result
func SafeExecuteWithResult[T any](rh *RecoveryHandler, ctx context.Context, operation string, fn func() (T, error)) (T, error) {
	var result T
	var err error
	
	defer func() {
		if recovered := recover(); recovered != nil {
			recoveryErr := rh.handleRecovery(ctx, recovered)
			rh.logger.WithFields(logrus.Fields{
				"operation": operation,
				"error":     recoveryErr.Error(),
			}).Error("Panic recovered during safe execution with result")
			err = recoveryErr
		}
	}()
	
	result, err = fn()
	return result, err
}

// ErrorReporter provides structured error reporting
type ErrorReporter struct {
	logger *logrus.Logger
}

// NewErrorReporter creates a new error reporter
func NewErrorReporter(logger *logrus.Logger) *ErrorReporter {
	if logger == nil {
		logger = logrus.New()
	}
	return &ErrorReporter{
		logger: logger,
	}
}

// ReportError reports an error with context
func (er *ErrorReporter) ReportError(ctx context.Context, err error, operation string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"operation": operation,
		"error":     err.Error(),
		"timestamp": time.Now().UTC(),
	}
	
	// Add context information
	if ctx != nil {
		if requestID := ctx.Value("request_id"); requestID != nil {
			fields["request_id"] = requestID
		}
		if userID := ctx.Value("user_id"); userID != nil {
			fields["user_id"] = userID
		}
	}
	
	// Add custom metadata
	for key, value := range metadata {
		fields[key] = value
	}
	
	// Determine log level based on error type (simplified for Generation 2)
	errorStr := err.Error()
	switch {
	case contains(errorStr, "validation") || contains(errorStr, "invalid"):
		er.logger.WithFields(fields).Warn("Validation error")
	case contains(errorStr, "not found") || contains(errorStr, "missing"):
		er.logger.WithFields(fields).Info("Resource not found")
	case contains(errorStr, "unauthorized") || contains(errorStr, "forbidden"):
		er.logger.WithFields(fields).Warn("Authentication/authorization error")
	default:
		er.logger.WithFields(fields).Error("Application error")
	}
}

// ReportCriticalError reports a critical error that requires immediate attention
func (er *ErrorReporter) ReportCriticalError(ctx context.Context, err error, operation string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"operation": operation,
		"error":     err.Error(),
		"timestamp": time.Now().UTC(),
		"severity":  "CRITICAL",
	}
	
	// Add context information
	if ctx != nil {
		if requestID := ctx.Value("request_id"); requestID != nil {
			fields["request_id"] = requestID
		}
		if userID := ctx.Value("user_id"); userID != nil {
			fields["user_id"] = userID
		}
	}
	
	// Add custom metadata
	for key, value := range metadata {
		fields[key] = value
	}
	
	er.logger.WithFields(fields).Fatal("Critical error occurred")
}

// HealthCheckError creates errors for health check failures
func HealthCheckError(component string, err error) error {
	return fmt.Errorf("health check failed for component %s: %w", component, err)
}

// contains checks if a string contains a substring (case-insensitive helper)
func contains(s, substr string) bool {
	// Simple case-insensitive contains for Generation 2
	s = fmt.Sprintf("%s", s)
	substr = fmt.Sprintf("%s", substr)
	return len(s) >= len(substr) && 
		   anyMatch(s, substr)
}

func anyMatch(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}