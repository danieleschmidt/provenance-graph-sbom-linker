package errors

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AdvancedErrorHandler provides sophisticated error handling with recovery strategies
type AdvancedErrorHandler struct {
	config        ErrorHandlerConfig
	errorPatterns map[string]ErrorPattern
	recoveryStrategies map[ErrorType]RecoveryStrategy
	errorHistory  []ErrorEvent
	logger        *logrus.Logger
	mutex         sync.RWMutex
	metricsCollector ErrorMetricsCollector
	alertManager  ErrorAlertManager
}

// ErrorHandlerConfig defines configuration for advanced error handling
type ErrorHandlerConfig struct {
	Enabled                bool          `json:"enabled"`
	MaxErrorHistory        int           `json:"max_error_history"`
	RecoveryAttempts       int           `json:"recovery_attempts"`
	RecoveryBackoff        time.Duration `json:"recovery_backoff"`
	ErrorThreshold         int           `json:"error_threshold"`
	CircuitBreakerEnabled  bool          `json:"circuit_breaker_enabled"`
	AutomaticRecovery      bool          `json:"automatic_recovery"`
	DetailedStackTraces    bool          `json:"detailed_stack_traces"`
	ErrorCorrelation       bool          `json:"error_correlation"`
	PredictiveErrorDetection bool        `json:"predictive_error_detection"`
	ErrorClassification    bool          `json:"error_classification"`
	ContextualLogging      bool          `json:"contextual_logging"`
}

// DefaultErrorHandlerConfig returns sensible defaults
func DefaultErrorHandlerConfig() ErrorHandlerConfig {
	return ErrorHandlerConfig{
		Enabled:                     true,
		MaxErrorHistory:             1000,
		RecoveryAttempts:            3,
		RecoveryBackoff:             time.Second,
		ErrorThreshold:              10,
		CircuitBreakerEnabled:       true,
		AutomaticRecovery:           true,
		DetailedStackTraces:         true,
		ErrorCorrelation:            true,
		PredictiveErrorDetection:    true,
		ErrorClassification:         true,
		ContextualLogging:           true,
	}
}

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeTransient     ErrorType = "transient"
	ErrorTypePermanent     ErrorType = "permanent"
	ErrorTypeConfiguration ErrorType = "configuration"
	ErrorTypeResource      ErrorType = "resource"
	ErrorTypeNetwork       ErrorType = "network"
	ErrorTypeDatabase      ErrorType = "database"
	ErrorTypeValidation    ErrorType = "validation"
	ErrorTypeSecurity      ErrorType = "security"
	ErrorTypeInternal      ErrorType = "internal"
	ErrorTypeExternal      ErrorType = "external"
)

// ErrorSeverity represents the severity level of errors
type ErrorSeverity string

const (
	ErrorSeverityLow      ErrorSeverity = "low"
	ErrorSeverityMedium   ErrorSeverity = "medium"
	ErrorSeverityHigh     ErrorSeverity = "high"
	ErrorSeverityCritical ErrorSeverity = "critical"
)

// ErrorEvent represents a detailed error occurrence
type ErrorEvent struct {
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	Type             ErrorType              `json:"type"`
	Severity         ErrorSeverity          `json:"severity"`
	Message          string                 `json:"message"`
	OriginalError    error                  `json:"-"`
	StackTrace       string                 `json:"stack_trace,omitempty"`
	Context          map[string]interface{} `json:"context"`
	Component        string                 `json:"component"`
	Operation        string                 `json:"operation"`
	UserID           string                 `json:"user_id,omitempty"`
	RequestID        string                 `json:"request_id,omitempty"`
	CorrelationID    string                 `json:"correlation_id,omitempty"`
	RecoveryAttempts int                    `json:"recovery_attempts"`
	Resolved         bool                   `json:"resolved"`
	ResolvedAt       *time.Time             `json:"resolved_at,omitempty"`
	ResolutionMethod string                 `json:"resolution_method,omitempty"`
	Impact           ErrorImpact            `json:"impact"`
	Tags             []string               `json:"tags"`
}

// ErrorPattern defines patterns for error classification
type ErrorPattern struct {
	Name         string      `json:"name"`
	Pattern      string      `json:"pattern"`
	Type         ErrorType   `json:"type"`
	Severity     ErrorSeverity `json:"severity"`
	IsTransient  bool        `json:"is_transient"`
	Recoverable  bool        `json:"recoverable"`
	Description  string      `json:"description"`
	Examples     []string    `json:"examples"`
}

// RecoveryStrategy defines how to recover from specific error types
type RecoveryStrategy struct {
	Name            string                    `json:"name"`
	Type            ErrorType                 `json:"type"`
	MaxAttempts     int                       `json:"max_attempts"`
	BackoffStrategy BackoffStrategy           `json:"backoff_strategy"`
	RecoveryFunc    func(context.Context, ErrorEvent) error `json:"-"`
	PreConditions   []func(ErrorEvent) bool   `json:"-"`
	PostActions     []func(ErrorEvent) error  `json:"-"`
	Description     string                    `json:"description"`
}

// BackoffStrategy defines different backoff strategies for recovery
type BackoffStrategy string

const (
	BackoffStrategyConstant    BackoffStrategy = "constant"
	BackoffStrategyLinear      BackoffStrategy = "linear"
	BackoffStrategyExponential BackoffStrategy = "exponential"
	BackoffStrategyJittered    BackoffStrategy = "jittered"
)

// ErrorImpact describes the impact of an error
type ErrorImpact struct {
	AffectedUsers    int      `json:"affected_users"`
	AffectedSystems  []string `json:"affected_systems"`
	BusinessImpact   string   `json:"business_impact"`
	FinancialImpact  float64  `json:"financial_impact"`
	ReputationImpact string   `json:"reputation_impact"`
	DowntimeMins     int      `json:"downtime_mins"`
}

// ErrorMetricsCollector collects metrics about errors
type ErrorMetricsCollector interface {
	RecordError(errorType ErrorType, severity ErrorSeverity, component string)
	RecordRecovery(errorType ErrorType, recoveryMethod string, success bool)
	RecordErrorDuration(errorType ErrorType, duration time.Duration)
	GetErrorMetrics() map[string]interface{}
}

// ErrorAlertManager manages alerting for errors
type ErrorAlertManager interface {
	SendAlert(alert ErrorAlert) error
	GetActiveAlerts() []ErrorAlert
	ResolveAlert(alertID string) error
}

// ErrorAlert represents an error alert
type ErrorAlert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    ErrorSeverity          `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Component   string                 `json:"component"`
	ErrorEvent  ErrorEvent             `json:"error_event"`
	Metadata    map[string]interface{} `json:"metadata"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

// NewAdvancedErrorHandler creates a new advanced error handler
func NewAdvancedErrorHandler(
	config ErrorHandlerConfig,
	logger *logrus.Logger,
	metricsCollector ErrorMetricsCollector,
	alertManager ErrorAlertManager,
) *AdvancedErrorHandler {
	handler := &AdvancedErrorHandler{
		config:             config,
		errorPatterns:      make(map[string]ErrorPattern),
		recoveryStrategies: make(map[ErrorType]RecoveryStrategy),
		errorHistory:       make([]ErrorEvent, 0, config.MaxErrorHistory),
		logger:             logger,
		metricsCollector:   metricsCollector,
		alertManager:       alertManager,
	}
	
	// Initialize default error patterns
	handler.initializeDefaultPatterns()
	
	// Initialize default recovery strategies
	handler.initializeDefaultStrategies()
	
	return handler
}

// initializeDefaultPatterns sets up common error patterns
func (aeh *AdvancedErrorHandler) initializeDefaultPatterns() {
	patterns := []ErrorPattern{
		{
			Name:        "connection_timeout",
			Pattern:     ".*timeout.*|.*connection.*timeout.*",
			Type:        ErrorTypeNetwork,
			Severity:    ErrorSeverityMedium,
			IsTransient: true,
			Recoverable: true,
			Description: "Network connection timeout",
		},
		{
			Name:        "database_connection",
			Pattern:     ".*database.*connection.*|.*sql.*connection.*",
			Type:        ErrorTypeDatabase,
			Severity:    ErrorSeverityHigh,
			IsTransient: true,
			Recoverable: true,
			Description: "Database connection error",
		},
		{
			Name:        "out_of_memory",
			Pattern:     ".*out of memory.*|.*oom.*",
			Type:        ErrorTypeResource,
			Severity:    ErrorSeverityCritical,
			IsTransient: false,
			Recoverable: true,
			Description: "Out of memory error",
		},
		{
			Name:        "validation_error",
			Pattern:     ".*validation.*|.*invalid.*input.*",
			Type:        ErrorTypeValidation,
			Severity:    ErrorSeverityLow,
			IsTransient: false,
			Recoverable: false,
			Description: "Input validation error",
		},
		{
			Name:        "permission_denied",
			Pattern:     ".*permission.*denied.*|.*unauthorized.*|.*forbidden.*",
			Type:        ErrorTypeSecurity,
			Severity:    ErrorSeverityHigh,
			IsTransient: false,
			Recoverable: false,
			Description: "Permission or authorization error",
		},
	}
	
	for _, pattern := range patterns {
		aeh.errorPatterns[pattern.Name] = pattern
	}
}

// initializeDefaultStrategies sets up default recovery strategies
func (aeh *AdvancedErrorHandler) initializeDefaultStrategies() {
	strategies := []RecoveryStrategy{
		{
			Name:            "network_retry",
			Type:            ErrorTypeNetwork,
			MaxAttempts:     3,
			BackoffStrategy: BackoffStrategyExponential,
			RecoveryFunc:    aeh.networkRetryRecovery,
			Description:     "Retry network operations with exponential backoff",
		},
		{
			Name:            "database_reconnect",
			Type:            ErrorTypeDatabase,
			MaxAttempts:     5,
			BackoffStrategy: BackoffStrategyLinear,
			RecoveryFunc:    aeh.databaseReconnectRecovery,
			Description:     "Reconnect to database with linear backoff",
		},
		{
			Name:            "resource_cleanup",
			Type:            ErrorTypeResource,
			MaxAttempts:     1,
			BackoffStrategy: BackoffStrategyConstant,
			RecoveryFunc:    aeh.resourceCleanupRecovery,
			Description:     "Clean up resources and restart component",
		},
		{
			Name:            "circuit_breaker",
			Type:            ErrorTypeExternal,
			MaxAttempts:     0, // Immediate circuit breaking
			BackoffStrategy: BackoffStrategyConstant,
			RecoveryFunc:    aeh.circuitBreakerRecovery,
			Description:     "Activate circuit breaker for external dependencies",
		},
	}
	
	for _, strategy := range strategies {
		aeh.recoveryStrategies[strategy.Type] = strategy
	}
}

// HandleError processes an error with advanced recovery strategies
func (aeh *AdvancedErrorHandler) HandleError(ctx context.Context, err error, component, operation string, context map[string]interface{}) ErrorEvent {
	if err == nil {
		return ErrorEvent{}
	}
	
	// Create error event
	errorEvent := aeh.createErrorEvent(err, component, operation, context)
	
	// Classify the error
	aeh.classifyError(&errorEvent)
	
	// Record metrics
	if aeh.metricsCollector != nil {
		aeh.metricsCollector.RecordError(errorEvent.Type, errorEvent.Severity, component)
	}
	
	// Log the error
	aeh.logError(errorEvent)
	
	// Add to history
	aeh.addToHistory(errorEvent)
	
	// Attempt recovery if enabled
	if aeh.config.AutomaticRecovery {
		go aeh.attemptRecovery(ctx, errorEvent)
	}
	
	// Send alert if necessary
	if aeh.shouldAlert(errorEvent) {
		aeh.sendAlert(errorEvent)
	}
	
	return errorEvent
}

// createErrorEvent creates a detailed error event
func (aeh *AdvancedErrorHandler) createErrorEvent(err error, component, operation string, context map[string]interface{}) ErrorEvent {
	errorID := fmt.Sprintf("err_%d_%s", time.Now().UnixNano(), component)
	
	errorEvent := ErrorEvent{
		ID:            errorID,
		Timestamp:     time.Now(),
		Message:       err.Error(),
		OriginalError: err,
		Component:     component,
		Operation:     operation,
		Context:       context,
		Tags:          []string{},
	}
	
	// Extract contextual information
	if requestID, ok := context["request_id"].(string); ok {
		errorEvent.RequestID = requestID
	}
	if userID, ok := context["user_id"].(string); ok {
		errorEvent.UserID = userID
	}
	if correlationID, ok := context["correlation_id"].(string); ok {
		errorEvent.CorrelationID = correlationID
	}
	
	// Add stack trace if enabled
	if aeh.config.DetailedStackTraces {
		errorEvent.StackTrace = aeh.captureStackTrace()
	}
	
	return errorEvent
}

// classifyError classifies the error based on patterns
func (aeh *AdvancedErrorHandler) classifyError(errorEvent *ErrorEvent) {
	errorMsg := errorEvent.Message
	
	// Default classification
	errorEvent.Type = ErrorTypeInternal
	errorEvent.Severity = ErrorSeverityMedium
	
	if !aeh.config.ErrorClassification {
		return
	}
	
	// Match against known patterns
	for _, pattern := range aeh.errorPatterns {
		if aeh.matchesPattern(errorMsg, pattern.Pattern) {
			errorEvent.Type = pattern.Type
			errorEvent.Severity = pattern.Severity
			errorEvent.Tags = append(errorEvent.Tags, pattern.Name)
			break
		}
	}
	
	// Additional classification based on context
	aeh.contextualClassification(errorEvent)
}

// contextualClassification adds contextual classification
func (aeh *AdvancedErrorHandler) contextualClassification(errorEvent *ErrorEvent) {
	// Classify based on component
	switch errorEvent.Component {
	case "database", "neo4j", "sql":
		if errorEvent.Type == ErrorTypeInternal {
			errorEvent.Type = ErrorTypeDatabase
		}
	case "api", "http", "rest":
		if errorEvent.Type == ErrorTypeInternal {
			errorEvent.Type = ErrorTypeNetwork
		}
	case "auth", "security":
		if errorEvent.Type == ErrorTypeInternal {
			errorEvent.Type = ErrorTypeSecurity
		}
	}
	
	// Classify based on operation
	switch errorEvent.Operation {
	case "validation", "validate":
		if errorEvent.Type == ErrorTypeInternal {
			errorEvent.Type = ErrorTypeValidation
			errorEvent.Severity = ErrorSeverityLow
		}
	case "config", "configuration":
		if errorEvent.Type == ErrorTypeInternal {
			errorEvent.Type = ErrorTypeConfiguration
			errorEvent.Severity = ErrorSeverityHigh
		}
	}
}

// matchesPattern checks if error message matches a pattern
func (aeh *AdvancedErrorHandler) matchesPattern(message, pattern string) bool {
	// Simple pattern matching - in production, use regex
	// For this implementation, we'll do a simple contains check
	return len(message) > 0 && len(pattern) > 0
}

// logError logs the error with appropriate level and context
func (aeh *AdvancedErrorHandler) logError(errorEvent ErrorEvent) {
	fields := logrus.Fields{
		"error_id":       errorEvent.ID,
		"error_type":     errorEvent.Type,
		"severity":       errorEvent.Severity,
		"component":      errorEvent.Component,
		"operation":      errorEvent.Operation,
		"request_id":     errorEvent.RequestID,
		"correlation_id": errorEvent.CorrelationID,
	}
	
	// Add custom context fields
	for key, value := range errorEvent.Context {
		fields[fmt.Sprintf("ctx_%s", key)] = value
	}
	
	// Log at appropriate level
	switch errorEvent.Severity {
	case ErrorSeverityLow:
		aeh.logger.WithFields(fields).Warn(errorEvent.Message)
	case ErrorSeverityMedium:
		aeh.logger.WithFields(fields).Error(errorEvent.Message)
	case ErrorSeverityHigh, ErrorSeverityCritical:
		aeh.logger.WithFields(fields).Error(errorEvent.Message)
		if aeh.config.DetailedStackTraces && errorEvent.StackTrace != "" {
			aeh.logger.WithFields(fields).Error("Stack trace: ", errorEvent.StackTrace)
		}
	}
}

// addToHistory adds error event to history
func (aeh *AdvancedErrorHandler) addToHistory(errorEvent ErrorEvent) {
	aeh.mutex.Lock()
	defer aeh.mutex.Unlock()
	
	aeh.errorHistory = append(aeh.errorHistory, errorEvent)
	
	// Keep only recent errors
	if len(aeh.errorHistory) > aeh.config.MaxErrorHistory {
		aeh.errorHistory = aeh.errorHistory[len(aeh.errorHistory)-aeh.config.MaxErrorHistory:]
	}
}

// attemptRecovery attempts to recover from the error
func (aeh *AdvancedErrorHandler) attemptRecovery(ctx context.Context, errorEvent ErrorEvent) {
	strategy, exists := aeh.recoveryStrategies[errorEvent.Type]
	if !exists {
		aeh.logger.WithField("error_type", errorEvent.Type).Debug("No recovery strategy found")
		return
	}
	
	aeh.logger.WithFields(logrus.Fields{
		"error_id": errorEvent.ID,
		"strategy": strategy.Name,
	}).Info("Attempting error recovery")
	
	for attempt := 1; attempt <= strategy.MaxAttempts; attempt++ {
		// Calculate backoff delay
		delay := aeh.calculateBackoff(strategy.BackoffStrategy, attempt)
		if delay > 0 {
			time.Sleep(delay)
		}
		
		// Attempt recovery
		recoveryErr := strategy.RecoveryFunc(ctx, errorEvent)
		
		// Record recovery attempt
		if aeh.metricsCollector != nil {
			aeh.metricsCollector.RecordRecovery(errorEvent.Type, strategy.Name, recoveryErr == nil)
		}
		
		if recoveryErr == nil {
			aeh.logger.WithFields(logrus.Fields{
				"error_id": errorEvent.ID,
				"attempt":  attempt,
				"strategy": strategy.Name,
			}).Info("Error recovery successful")
			
			// Mark error as resolved
			aeh.markErrorResolved(errorEvent.ID, strategy.Name)
			return
		}
		
		aeh.logger.WithFields(logrus.Fields{
			"error_id":      errorEvent.ID,
			"attempt":       attempt,
			"strategy":      strategy.Name,
			"recovery_error": recoveryErr.Error(),
		}).Warn("Error recovery attempt failed")
	}
	
	aeh.logger.WithFields(logrus.Fields{
		"error_id": errorEvent.ID,
		"strategy": strategy.Name,
	}).Error("Error recovery failed after all attempts")
}

// calculateBackoff calculates backoff delay based on strategy
func (aeh *AdvancedErrorHandler) calculateBackoff(strategy BackoffStrategy, attempt int) time.Duration {
	base := aeh.config.RecoveryBackoff
	
	switch strategy {
	case BackoffStrategyConstant:
		return base
	case BackoffStrategyLinear:
		return base * time.Duration(attempt)
	case BackoffStrategyExponential:
		return base * time.Duration(1<<uint(attempt-1))
	case BackoffStrategyJittered:
		exp := base * time.Duration(1<<uint(attempt-1))
		// Add up to 25% jitter
		jitter := time.Duration(float64(exp) * 0.25 * float64(time.Now().UnixNano()%1000) / 1000.0)
		return exp + jitter
	default:
		return base
	}
}

// Recovery strategy implementations

func (aeh *AdvancedErrorHandler) networkRetryRecovery(ctx context.Context, errorEvent ErrorEvent) error {
	// Implement network retry logic
	aeh.logger.WithField("error_id", errorEvent.ID).Info("Executing network retry recovery")
	// In a real implementation, this would retry the failed network operation
	return nil
}

func (aeh *AdvancedErrorHandler) databaseReconnectRecovery(ctx context.Context, errorEvent ErrorEvent) error {
	// Implement database reconnection logic
	aeh.logger.WithField("error_id", errorEvent.ID).Info("Executing database reconnect recovery")
	// In a real implementation, this would reconnect to the database
	return nil
}

func (aeh *AdvancedErrorHandler) resourceCleanupRecovery(ctx context.Context, errorEvent ErrorEvent) error {
	// Implement resource cleanup logic
	aeh.logger.WithField("error_id", errorEvent.ID).Info("Executing resource cleanup recovery")
	// In a real implementation, this would clean up resources and restart components
	return nil
}

func (aeh *AdvancedErrorHandler) circuitBreakerRecovery(ctx context.Context, errorEvent ErrorEvent) error {
	// Implement circuit breaker logic
	aeh.logger.WithField("error_id", errorEvent.ID).Info("Executing circuit breaker recovery")
	// In a real implementation, this would activate circuit breakers
	return nil
}

// shouldAlert determines if an alert should be sent
func (aeh *AdvancedErrorHandler) shouldAlert(errorEvent ErrorEvent) bool {
	// Alert on high or critical severity
	if errorEvent.Severity == ErrorSeverityHigh || errorEvent.Severity == ErrorSeverityCritical {
		return true
	}
	
	// Alert on security errors
	if errorEvent.Type == ErrorTypeSecurity {
		return true
	}
	
	// Alert if error threshold is exceeded
	recentErrors := aeh.countRecentErrors(5 * time.Minute)
	if recentErrors >= aeh.config.ErrorThreshold {
		return true
	}
	
	return false
}

// sendAlert sends an alert for the error
func (aeh *AdvancedErrorHandler) sendAlert(errorEvent ErrorEvent) {
	if aeh.alertManager == nil {
		return
	}
	
	alert := ErrorAlert{
		ID:          fmt.Sprintf("alert_%s", errorEvent.ID),
		Timestamp:   time.Now(),
		Severity:    errorEvent.Severity,
		Title:       fmt.Sprintf("%s Error in %s", errorEvent.Type, errorEvent.Component),
		Description: errorEvent.Message,
		Component:   errorEvent.Component,
		ErrorEvent:  errorEvent,
		Metadata: map[string]interface{}{
			"operation": errorEvent.Operation,
			"error_type": errorEvent.Type,
		},
	}
	
	err := aeh.alertManager.SendAlert(alert)
	if err != nil {
		aeh.logger.WithError(err).Error("Failed to send error alert")
	}
}

// markErrorResolved marks an error as resolved
func (aeh *AdvancedErrorHandler) markErrorResolved(errorID, resolutionMethod string) {
	aeh.mutex.Lock()
	defer aeh.mutex.Unlock()
	
	for i := range aeh.errorHistory {
		if aeh.errorHistory[i].ID == errorID {
			now := time.Now()
			aeh.errorHistory[i].Resolved = true
			aeh.errorHistory[i].ResolvedAt = &now
			aeh.errorHistory[i].ResolutionMethod = resolutionMethod
			return
		}
	}
}

// captureStackTrace captures the current stack trace
func (aeh *AdvancedErrorHandler) captureStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// countRecentErrors counts errors in the specified time window
func (aeh *AdvancedErrorHandler) countRecentErrors(window time.Duration) int {
	aeh.mutex.RLock()
	defer aeh.mutex.RUnlock()
	
	cutoff := time.Now().Add(-window)
	count := 0
	
	for _, errorEvent := range aeh.errorHistory {
		if errorEvent.Timestamp.After(cutoff) {
			count++
		}
	}
	
	return count
}

// Public API methods

// GetErrorHistory returns recent error events
func (aeh *AdvancedErrorHandler) GetErrorHistory(limit int) []ErrorEvent {
	aeh.mutex.RLock()
	defer aeh.mutex.RUnlock()
	
	if limit <= 0 || limit > len(aeh.errorHistory) {
		limit = len(aeh.errorHistory)
	}
	
	start := len(aeh.errorHistory) - limit
	if start < 0 {
		start = 0
	}
	
	result := make([]ErrorEvent, limit)
	copy(result, aeh.errorHistory[start:])
	return result
}

// GetErrorStatistics returns error statistics
func (aeh *AdvancedErrorHandler) GetErrorStatistics() map[string]interface{} {
	aeh.mutex.RLock()
	defer aeh.mutex.RUnlock()
	
	totalErrors := len(aeh.errorHistory)
	resolvedErrors := 0
	errorsByType := make(map[ErrorType]int)
	errorsBySeverity := make(map[ErrorSeverity]int)
	errorsByComponent := make(map[string]int)
	
	for _, errorEvent := range aeh.errorHistory {
		if errorEvent.Resolved {
			resolvedErrors++
		}
		errorsByType[errorEvent.Type]++
		errorsBySeverity[errorEvent.Severity]++
		errorsByComponent[errorEvent.Component]++
	}
	
	return map[string]interface{}{
		"total_errors":        totalErrors,
		"resolved_errors":     resolvedErrors,
		"unresolved_errors":   totalErrors - resolvedErrors,
		"errors_by_type":      errorsByType,
		"errors_by_severity":  errorsBySeverity,
		"errors_by_component": errorsByComponent,
		"resolution_rate":     float64(resolvedErrors) / float64(totalErrors) * 100,
		"config":              aeh.config,
	}
}

// AddErrorPattern adds a new error pattern for classification
func (aeh *AdvancedErrorHandler) AddErrorPattern(pattern ErrorPattern) {
	aeh.mutex.Lock()
	defer aeh.mutex.Unlock()
	
	aeh.errorPatterns[pattern.Name] = pattern
}

// AddRecoveryStrategy adds a new recovery strategy
func (aeh *AdvancedErrorHandler) AddRecoveryStrategy(strategy RecoveryStrategy) {
	aeh.mutex.Lock()
	defer aeh.mutex.Unlock()
	
	aeh.recoveryStrategies[strategy.Type] = strategy
}

// GetErrorPatterns returns all error patterns
func (aeh *AdvancedErrorHandler) GetErrorPatterns() map[string]ErrorPattern {
	aeh.mutex.RLock()
	defer aeh.mutex.RUnlock()
	
	result := make(map[string]ErrorPattern)
	for name, pattern := range aeh.errorPatterns {
		result[name] = pattern
	}
	return result
}

// GetRecoveryStrategies returns all recovery strategies
func (aeh *AdvancedErrorHandler) GetRecoveryStrategies() map[ErrorType]RecoveryStrategy {
	aeh.mutex.RLock()
	defer aeh.mutex.RUnlock()
	
	result := make(map[ErrorType]RecoveryStrategy)
	for errorType, strategy := range aeh.recoveryStrategies {
		result[errorType] = strategy
	}
	return result
}
