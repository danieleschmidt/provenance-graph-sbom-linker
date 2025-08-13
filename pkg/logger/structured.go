package logger

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
)

// StructuredLogger provides structured logging with security, performance, and audit capabilities
type StructuredLogger struct {
	logger *logrus.Logger
	level  string
	format string
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Level      string                 `json:"level"`
	Message    string                 `json:"message"`
	Timestamp  time.Time              `json:"timestamp"`
	TraceID    string                 `json:"trace_id,omitempty"`
	SpanID     string                 `json:"span_id,omitempty"`
	Service    string                 `json:"service"`
	Component  string                 `json:"component,omitempty"`
	Operation  string                 `json:"operation,omitempty"`
	UserID     string                 `json:"user_id,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	RequestID  string                 `json:"request_id,omitempty"`
	ClientIP   string                 `json:"client_ip,omitempty"`
	Duration   time.Duration          `json:"duration,omitempty"`
	StatusCode int                    `json:"status_code,omitempty"`
	Error      *ErrorInfo             `json:"error,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Caller     *CallerInfo            `json:"caller,omitempty"`
}

// ErrorInfo provides detailed error information for logging
type ErrorInfo struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	Stack      string `json:"stack,omitempty"`
	ErrorID    string `json:"error_id,omitempty"`
	Component  string `json:"component,omitempty"`
	Recoverable bool  `json:"recoverable"`
}

// CallerInfo provides source code location information
type CallerInfo struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Line     int    `json:"line"`
}

// AuditEvent represents a security audit event
type AuditEvent struct {
	EventType    string                 `json:"event_type"`
	Actor        string                 `json:"actor"`
	Resource     string                 `json:"resource"`
	Action       string                 `json:"action"`
	Outcome      string                 `json:"outcome"`
	Timestamp    time.Time              `json:"timestamp"`
	ClientIP     string                 `json:"client_ip,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	RiskLevel    string                 `json:"risk_level"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PerformanceMetric represents a performance measurement
type PerformanceMetric struct {
	Operation   string                 `json:"operation"`
	Duration    time.Duration          `json:"duration"`
	Success     bool                   `json:"success"`
	Timestamp   time.Time              `json:"timestamp"`
	Component   string                 `json:"component"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Thresholds  map[string]time.Duration `json:"thresholds,omitempty"`
	Violated    []string               `json:"threshold_violations,omitempty"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	EventType    string                 `json:"event_type"`
	Severity     string                 `json:"severity"`
	Source       string                 `json:"source"`
	Description  string                 `json:"description"`
	ClientIP     string                 `json:"client_ip"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	RequestPath  string                 `json:"request_path,omitempty"`
	Method       string                 `json:"method,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Indicators   []string               `json:"indicators,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Blocked      bool                   `json:"blocked"`
	Action       string                 `json:"action"`
}

// NewStructuredLogger creates a new structured logger instance
func NewStructuredLogger(level, format string) *StructuredLogger {
	logger := logrus.New()
	
	// Set log level
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)
	
	// Set formatter
	if format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	}
	
	// Output to stdout for container environments
	logger.SetOutput(os.Stdout)
	
	return &StructuredLogger{
		logger: logger,
		level:  level,
		format: format,
	}
}

// Info logs an informational message
func (sl *StructuredLogger) Info(message string, metadata map[string]interface{}) {
	entry := sl.createEntry("info", message, metadata)
	sl.writeEntry(entry)
}

// Warn logs a warning message
func (sl *StructuredLogger) Warn(message string, metadata map[string]interface{}) {
	entry := sl.createEntry("warn", message, metadata)
	sl.writeEntry(entry)
}

// Error logs an error message
func (sl *StructuredLogger) Error(message string, metadata map[string]interface{}) {
	entry := sl.createEntry("error", message, metadata)
	entry.Caller = sl.getCaller(3)
	sl.writeEntry(entry)
}

// Debug logs a debug message
func (sl *StructuredLogger) Debug(message string, metadata map[string]interface{}) {
	entry := sl.createEntry("debug", message, metadata)
	sl.writeEntry(entry)
}

// LogError logs an error with context and stack trace
func (sl *StructuredLogger) LogError(ctx context.Context, err error, operation string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	
	entry := sl.createEntry("error", fmt.Sprintf("Operation failed: %s", operation), metadata)
	entry.Operation = operation
	entry.Error = &ErrorInfo{
		Type:        "application_error",
		Message:     err.Error(),
		Stack:       sl.getStackTrace(),
		Component:   operation,
		Recoverable: sl.isRecoverableError(err),
	}
	
	// Add trace context if available
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		entry.TraceID = span.SpanContext().TraceID().String()
		entry.SpanID = span.SpanContext().SpanID().String()
	}
	
	sl.writeEntry(entry)
}

// Performance logs performance metrics with threshold monitoring
func (sl *StructuredLogger) Performance(operation string, duration time.Duration, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	
	// Define performance thresholds
	thresholds := map[string]time.Duration{
		"critical": 5 * time.Second,
		"warning":  1 * time.Second,
		"optimal":  100 * time.Millisecond,
	}
	
	var violations []string
	if duration > thresholds["critical"] {
		violations = append(violations, "critical")
	} else if duration > thresholds["warning"] {
		violations = append(violations, "warning")
	}
	
	metric := PerformanceMetric{
		Operation:  operation,
		Duration:   duration,
		Success:    len(violations) == 0,
		Timestamp:  time.Now(),
		Component:  "performance-monitor",
		Metadata:   metadata,
		Thresholds: thresholds,
		Violated:   violations,
	}
	
	level := "info"
	if len(violations) > 0 {
		level = "warn"
		if duration > thresholds["critical"] {
			level = "error"
		}
	}
	
	entry := sl.createEntry(level, fmt.Sprintf("Performance metric: %s", operation), map[string]interface{}{
		"performance": metric,
	})
	
	sl.writeEntry(entry)
}

// Audit logs security audit events
func (sl *StructuredLogger) Audit(action, actor, resource string, success bool, metadata map[string]interface{}) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	
	riskLevel := "low"
	if !success {
		riskLevel = "medium"
	}
	
	// Determine risk level based on action
	if strings.Contains(strings.ToLower(action), "delete") || 
	   strings.Contains(strings.ToLower(action), "admin") {
		riskLevel = "high"
	}
	
	auditEvent := AuditEvent{
		EventType: "user_action",
		Actor:     actor,
		Resource:  resource,
		Action:    action,
		Outcome:   outcome,
		Timestamp: time.Now(),
		RiskLevel: riskLevel,
		Metadata:  metadata,
	}
	
	entry := sl.createEntry("info", fmt.Sprintf("Audit: %s %s %s", actor, action, resource), map[string]interface{}{
		"audit": auditEvent,
	})
	
	sl.writeEntry(entry)
}

// Security logs security events with threat intelligence
func (sl *StructuredLogger) Security(eventType, severity, source, description, clientIP string, metadata map[string]interface{}) {
	securityEvent := SecurityEvent{
		EventType:   eventType,
		Severity:    severity,
		Source:      source,
		Description: description,
		ClientIP:    clientIP,
		Timestamp:   time.Now(),
		Metadata:    metadata,
		Blocked:     severity == "high" || severity == "critical",
		Action:      sl.determineSecurityAction(severity),
	}
	
	// Add threat indicators
	indicators := sl.extractThreatIndicators(description, clientIP, metadata)
	securityEvent.Indicators = indicators
	
	level := "info"
	switch severity {
	case "critical":
		level = "error"
	case "high":
		level = "error"
	case "medium":
		level = "warn"
	case "low":
		level = "info"
	}
	
	entry := sl.createEntry(level, fmt.Sprintf("Security event: %s", description), map[string]interface{}{
		"security": securityEvent,
	})
	
	sl.writeEntry(entry)
}

// Helper methods

func (sl *StructuredLogger) createEntry(level, message string, metadata map[string]interface{}) *LogEntry {
	return &LogEntry{
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
		Service:   "provenance-linker",
		Metadata:  metadata,
	}
}

func (sl *StructuredLogger) writeEntry(entry *LogEntry) {
	fields := logrus.Fields{
		"service":   entry.Service,
		"timestamp": entry.Timestamp,
	}
	
	if entry.TraceID != "" {
		fields["trace_id"] = entry.TraceID
	}
	if entry.SpanID != "" {
		fields["span_id"] = entry.SpanID
	}
	if entry.Component != "" {
		fields["component"] = entry.Component
	}
	if entry.Operation != "" {
		fields["operation"] = entry.Operation
	}
	if entry.Error != nil {
		fields["error"] = entry.Error
	}
	if entry.Caller != nil {
		fields["caller"] = entry.Caller
	}
	if entry.Duration > 0 {
		fields["duration_ms"] = entry.Duration.Milliseconds()
	}
	if entry.StatusCode > 0 {
		fields["status_code"] = entry.StatusCode
	}
	
	// Add metadata
	if entry.Metadata != nil {
		for k, v := range entry.Metadata {
			fields[k] = v
		}
	}
	
	switch entry.Level {
	case "debug":
		sl.logger.WithFields(fields).Debug(entry.Message)
	case "info":
		sl.logger.WithFields(fields).Info(entry.Message)
	case "warn":
		sl.logger.WithFields(fields).Warn(entry.Message)
	case "error":
		sl.logger.WithFields(fields).Error(entry.Message)
	}
}

func (sl *StructuredLogger) getCaller(skip int) *CallerInfo {
	_, file, line, ok := runtime.Caller(skip)
	if !ok {
		return nil
	}
	
	pc, _, _, ok := runtime.Caller(skip)
	if !ok {
		return nil
	}
	
	funcName := runtime.FuncForPC(pc).Name()
	
	return &CallerInfo{
		File:     file,
		Function: funcName,
		Line:     line,
	}
}

func (sl *StructuredLogger) getStackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	
	var stack strings.Builder
	for {
		frame, more := frames.Next()
		stack.WriteString(fmt.Sprintf("%s:%d %s\n", frame.File, frame.Line, frame.Function))
		if !more {
			break
		}
	}
	return stack.String()
}

func (sl *StructuredLogger) isRecoverableError(err error) bool {
	// Simple heuristic to determine if error is recoverable
	errStr := strings.ToLower(err.Error())
	unrecoverable := []string{"panic", "fatal", "out of memory", "disk full"}
	
	for _, pattern := range unrecoverable {
		if strings.Contains(errStr, pattern) {
			return false
		}
	}
	return true
}

func (sl *StructuredLogger) determineSecurityAction(severity string) string {
	switch severity {
	case "critical":
		return "block_and_alert"
	case "high":
		return "block"
	case "medium":
		return "monitor"
	default:
		return "log"
	}
}

func (sl *StructuredLogger) extractThreatIndicators(description, clientIP string, metadata map[string]interface{}) []string {
	var indicators []string
	
	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"sql injection", "xss", "csrf", "directory traversal",
		"command injection", "file inclusion", "xxe",
	}
	
	descLower := strings.ToLower(description)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(descLower, pattern) {
			indicators = append(indicators, pattern)
		}
	}
	
	// Check for suspicious IP patterns
	if sl.isSuspiciousIP(clientIP) {
		indicators = append(indicators, "suspicious_ip")
	}
	
	// Check metadata for additional indicators
	if metadata != nil {
		if userAgent, exists := metadata["user_agent"]; exists {
			if sl.isSuspiciousUserAgent(fmt.Sprintf("%v", userAgent)) {
				indicators = append(indicators, "suspicious_user_agent")
			}
		}
	}
	
	return indicators
}

func (sl *StructuredLogger) isSuspiciousIP(ip string) bool {
	// Simple check for private IPs (in production, integrate with threat intelligence)
	suspiciousRanges := []string{
		"10.", "172.", "192.168.", "127.", "0.", "255.",
	}
	
	for _, prefix := range suspiciousRanges {
		if strings.HasPrefix(ip, prefix) {
			return false // Private IPs are not suspicious in this context
		}
	}
	
	// In production, check against threat intelligence feeds
	return false
}

func (sl *StructuredLogger) isSuspiciousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"sqlmap", "nikto", "nmap", "masscan", "nessus",
		"burp", "dirbuster", "gobuster", "wfuzz",
	}
	
	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}
	
	return false
}