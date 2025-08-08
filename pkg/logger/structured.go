package logger

import (
	"context"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
)

type StructuredLogger struct {
	*logrus.Logger
}

type LogEntry struct {
	*logrus.Entry
}

func NewStructuredLogger(level string, format string) *StructuredLogger {
	logger := logrus.New()
	
	// Set log level
	switch level {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	// Set formatter
	if format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
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

	logger.SetOutput(os.Stdout)
	
	return &StructuredLogger{Logger: logger}
}

func (l *StructuredLogger) WithContext(ctx context.Context) *LogEntry {
	entry := l.Logger.WithContext(ctx)
	
	// Add tracing information if available
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		entry = entry.WithFields(logrus.Fields{
			"trace_id": spanCtx.TraceID().String(),
			"span_id":  spanCtx.SpanID().String(),
		})
	}
	
	return &LogEntry{Entry: entry}
}

func (l *StructuredLogger) WithFields(fields logrus.Fields) *LogEntry {
	return &LogEntry{Entry: l.Logger.WithFields(fields)}
}

func (l *StructuredLogger) WithError(err error) *LogEntry {
	return &LogEntry{Entry: l.Logger.WithError(err)}
}

func (e *LogEntry) WithField(key string, value interface{}) *LogEntry {
	return &LogEntry{Entry: e.Entry.WithField(key, value)}
}

func (e *LogEntry) WithFields(fields logrus.Fields) *LogEntry {
	return &LogEntry{Entry: e.Entry.WithFields(fields)}
}

func (e *LogEntry) WithError(err error) *LogEntry {
	return &LogEntry{Entry: e.Entry.WithError(err)}
}

// Audit logging for security events
func (l *StructuredLogger) Audit(action, user, resource string, success bool, details map[string]interface{}) {
	fields := logrus.Fields{
		"event_type": "audit",
		"action":     action,
		"user":       user,
		"resource":   resource,
		"success":    success,
		"timestamp":  time.Now().UTC(),
	}
	
	for k, v := range details {
		fields[k] = v
	}
	
	l.WithFields(fields).Info("Security audit event")
}

// Performance logging
func (l *StructuredLogger) Performance(operation string, duration time.Duration, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"event_type":        "performance",
		"operation":         operation,
		"duration_ms":       duration.Milliseconds(),
		"duration_seconds":  duration.Seconds(),
	}
	
	for k, v := range metadata {
		fields[k] = v
	}
	
	l.WithFields(fields).Info("Performance measurement")
}

// Error logging with context
func (l *StructuredLogger) LogError(ctx context.Context, err error, operation string, metadata map[string]interface{}) {
	entry := l.WithContext(ctx).WithError(err)
	
	fields := logrus.Fields{
		"operation": operation,
		"error_type": getErrorType(err),
	}
	
	for k, v := range metadata {
		fields[k] = v
	}
	
	entry.WithFields(fields).Error("Operation failed")
}

func getErrorType(err error) string {
	if err == nil {
		return "none"
	}
	
	// Basic error type detection
	switch {
	case isValidationError(err):
		return "validation"
	case isNotFoundError(err):
		return "not_found"
	case isUnauthorizedError(err):
		return "unauthorized"
	case isNetworkError(err):
		return "network"
	default:
		return "unknown"
	}
}

func isValidationError(err error) bool {
	// Check if error is validation-related
	return false // Placeholder implementation
}

func isNotFoundError(err error) bool {
	// Check if error is not found-related
	return false // Placeholder implementation
}

func isUnauthorizedError(err error) bool {
	// Check if error is authorization-related
	return false // Placeholder implementation
}

func isNetworkError(err error) bool {
	// Check if error is network-related
	return false // Placeholder implementation
}