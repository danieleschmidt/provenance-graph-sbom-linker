package resilience

import (
	"context"
	"fmt"
	"math"
	"time"
)

// RetryConfig defines retry behavior
type RetryConfig struct {
	MaxAttempts     int           `yaml:"max_attempts" json:"max_attempts"`
	BaseDelay       time.Duration `yaml:"base_delay" json:"base_delay"`
	MaxDelay        time.Duration `yaml:"max_delay" json:"max_delay"`
	BackoffFactor   float64       `yaml:"backoff_factor" json:"backoff_factor"`
	RetryableErrors []string      `yaml:"retryable_errors" json:"retryable_errors"`
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:   3,
		BaseDelay:     time.Millisecond * 100,
		MaxDelay:      time.Second * 30,
		BackoffFactor: 2.0,
		RetryableErrors: []string{
			"connection refused",
			"timeout",
			"temporary failure",
			"service unavailable",
		},
	}
}

// RetryFunc represents a function that can be retried
type RetryFunc func() error

// RetryWithContext executes a function with exponential backoff and jitter
func (rc *RetryConfig) RetryWithContext(ctx context.Context, operation string, fn RetryFunc) error {
	var lastErr error
	
	for attempt := 1; attempt <= rc.MaxAttempts; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		// Execute the function
		err := fn()
		if err == nil {
			return nil // Success
		}
		
		lastErr = err
		
		// Don't retry on the last attempt
		if attempt == rc.MaxAttempts {
			break
		}
		
		// Check if error is retryable
		if !rc.isRetryableError(err) {
			return fmt.Errorf("non-retryable error on attempt %d: %w", attempt, err)
		}
		
		// Calculate delay with exponential backoff and jitter
		delay := rc.calculateDelay(attempt)
		
		// Wait before next attempt
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			// Continue to next attempt
		}
	}
	
	return fmt.Errorf("operation '%s' failed after %d attempts, last error: %w", 
		operation, rc.MaxAttempts, lastErr)
}

// Retry executes a function with retry logic (without context)
func (rc *RetryConfig) Retry(operation string, fn RetryFunc) error {
	return rc.RetryWithContext(context.Background(), operation, fn)
}

// calculateDelay calculates the delay for the given attempt with exponential backoff and jitter
func (rc *RetryConfig) calculateDelay(attempt int) time.Duration {
	// Exponential backoff: delay = baseDelay * (backoffFactor ^ (attempt-1))
	exponentialDelay := time.Duration(float64(rc.BaseDelay) * math.Pow(rc.BackoffFactor, float64(attempt-1)))
	
	// Cap at max delay
	if exponentialDelay > rc.MaxDelay {
		exponentialDelay = rc.MaxDelay
	}
	
	// Add jitter (up to 10% of the delay)
	jitter := time.Duration(float64(exponentialDelay) * 0.1 * (2*time.Now().UnixNano()%1000/1000.0 - 1))
	delay := exponentialDelay + jitter
	
	// Ensure minimum delay
	if delay < rc.BaseDelay {
		delay = rc.BaseDelay
	}
	
	return delay
}

// isRetryableError checks if an error should be retried
func (rc *RetryConfig) isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	
	errStr := err.Error()
	for _, retryableError := range rc.RetryableErrors {
		if contains(errStr, retryableError) {
			return true
		}
	}
	
	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    (len(s) > len(substr) && 
		     anyMatch(s, substr)))
}

func anyMatch(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// RetryableFunc is a function type that includes retry metadata
type RetryableFunc struct {
	Function    RetryFunc
	Operation   string
	Config      *RetryConfig
}

// NewRetryableFunc creates a new retryable function
func NewRetryableFunc(operation string, fn RetryFunc, config *RetryConfig) *RetryableFunc {
	if config == nil {
		config = DefaultRetryConfig()
	}
	
	return &RetryableFunc{
		Function:  fn,
		Operation: operation,
		Config:    config,
	}
}

// Execute runs the retryable function
func (rf *RetryableFunc) Execute() error {
	return rf.Config.Retry(rf.Operation, rf.Function)
}

// ExecuteWithContext runs the retryable function with context
func (rf *RetryableFunc) ExecuteWithContext(ctx context.Context) error {
	return rf.Config.RetryWithContext(ctx, rf.Operation, rf.Function)
}