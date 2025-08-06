package logger

import (
	"context"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

type contextKey string

const (
	CorrelationIDKey contextKey = "correlation_id"
	UserIDKey       contextKey = "user_id"
	RequestIDKey    contextKey = "request_id"
)

var defaultLogger *Logger

func init() {
	defaultLogger = NewLogger("info", "json")
}

func NewLogger(level, format string) *Logger {
	logger := logrus.New()
	
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)

	switch format {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "caller",
			},
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	default:
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	}

	logger.SetOutput(os.Stdout)
	logger.SetReportCaller(true)

	return &Logger{Logger: logger}
}

func (l *Logger) WithContext(ctx context.Context) *logrus.Entry {
	entry := l.Logger.WithFields(logrus.Fields{})

	if correlationID, ok := ctx.Value(CorrelationIDKey).(string); ok && correlationID != "" {
		entry = entry.WithField("correlation_id", correlationID)
	}

	if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
		entry = entry.WithField("user_id", userID)
	}

	if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
		entry = entry.WithField("request_id", requestID)
	}

	return entry
}

func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

func (l *Logger) WithFields(fields logrus.Fields) *logrus.Entry {
	return l.Logger.WithFields(fields)
}

func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

func GetDefault() *Logger {
	return defaultLogger
}

func WithContext(ctx context.Context) *logrus.Entry {
	return defaultLogger.WithContext(ctx)
}

func WithError(err error) *logrus.Entry {
	return defaultLogger.WithError(err)
}

func WithFields(fields logrus.Fields) *logrus.Entry {
	return defaultLogger.WithFields(fields)
}

func WithField(key string, value interface{}) *logrus.Entry {
	return defaultLogger.WithField(key, value)
}

func Info(args ...interface{}) {
	defaultLogger.Info(args...)
}

func Infof(format string, args ...interface{}) {
	defaultLogger.Infof(format, args...)
}

func Warn(args ...interface{}) {
	defaultLogger.Warn(args...)
}

func Warnf(format string, args ...interface{}) {
	defaultLogger.Warnf(format, args...)
}

func Error(args ...interface{}) {
	defaultLogger.Error(args...)
}

func Errorf(format string, args ...interface{}) {
	defaultLogger.Errorf(format, args...)
}

func Debug(args ...interface{}) {
	defaultLogger.Debug(args...)
}

func Debugf(format string, args ...interface{}) {
	defaultLogger.Debugf(format, args...)
}

func Fatal(args ...interface{}) {
	defaultLogger.Fatal(args...)
}

func Fatalf(format string, args ...interface{}) {
	defaultLogger.Fatalf(format, args...)
}

func Panic(args ...interface{}) {
	defaultLogger.Panic(args...)
}

func Panicf(format string, args ...interface{}) {
	defaultLogger.Panicf(format, args...)
}