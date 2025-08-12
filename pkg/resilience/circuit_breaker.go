package resilience

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	// StateClosed allows requests through
	StateClosed CircuitBreakerState = iota
	// StateOpen rejects requests immediately
	StateOpen
	// StateHalfOpen allows limited requests through for testing
	StateHalfOpen
)

func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreakerConfig holds configuration for a circuit breaker
type CircuitBreakerConfig struct {
	// MaxFailures is the maximum number of failures before opening the circuit
	MaxFailures int
	// ResetTimeout is how long to wait before transitioning from OPEN to HALF_OPEN
	ResetTimeout time.Duration
	// MaxHalfOpenRequests is the maximum number of requests allowed in HALF_OPEN state
	MaxHalfOpenRequests int
	// SuccessThreshold is the number of consecutive successes needed to close the circuit
	SuccessThreshold int
	// Name is an identifier for this circuit breaker
	Name string
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config   CircuitBreakerConfig
	state    CircuitBreakerState
	failures int
	successes int
	requests int
	lastFailureTime time.Time
	mu       sync.RWMutex
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	if config.MaxFailures <= 0 {
		config.MaxFailures = 5
	}
	if config.ResetTimeout <= 0 {
		config.ResetTimeout = 30 * time.Second
	}
	if config.MaxHalfOpenRequests <= 0 {
		config.MaxHalfOpenRequests = 3
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = 2
	}
	if config.Name == "" {
		config.Name = "default"
	}

	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
	}
}

// Execute runs the provided function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(ctx context.Context) error) error {
	// Check if we can execute
	if !cb.canExecute() {
		return &CircuitBreakerError{
			State:   cb.getState(),
			Message: fmt.Sprintf("circuit breaker %s is %s", cb.config.Name, cb.getState()),
		}
	}

	// Track the request
	cb.beforeRequest()

	// Execute the function
	err := fn(ctx)

	// Handle the result
	cb.afterRequest(err)

	return err
}

// canExecute determines if a request can be executed
func (cb *CircuitBreaker) canExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if we should transition to half-open
		if time.Since(cb.lastFailureTime) >= cb.config.ResetTimeout {
			return true
		}
		return false
	case StateHalfOpen:
		return cb.requests < cb.config.MaxHalfOpenRequests
	default:
		return false
	}
}

// beforeRequest is called before executing a request
func (cb *CircuitBreaker) beforeRequest() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Transition from OPEN to HALF_OPEN if timeout has elapsed
	if cb.state == StateOpen && time.Since(cb.lastFailureTime) >= cb.config.ResetTimeout {
		cb.state = StateHalfOpen
		cb.requests = 0
		cb.successes = 0
	}

	if cb.state == StateHalfOpen {
		cb.requests++
	}
}

// afterRequest is called after executing a request
func (cb *CircuitBreaker) afterRequest(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.onFailure()
	} else {
		cb.onSuccess()
	}
}

// onFailure handles a failed request
func (cb *CircuitBreaker) onFailure() {
	cb.failures++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case StateClosed:
		if cb.failures >= cb.config.MaxFailures {
			cb.state = StateOpen
		}
	case StateHalfOpen:
		cb.state = StateOpen
		cb.requests = 0
		cb.successes = 0
	}
}

// onSuccess handles a successful request
func (cb *CircuitBreaker) onSuccess() {
	cb.failures = 0

	switch cb.state {
	case StateHalfOpen:
		cb.successes++
		if cb.successes >= cb.config.SuccessThreshold {
			cb.state = StateClosed
			cb.requests = 0
			cb.successes = 0
		}
	}
}

// getState returns the current state
func (cb *CircuitBreaker) getState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetMetrics returns current circuit breaker metrics
func (cb *CircuitBreaker) GetMetrics() CircuitBreakerMetrics {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return CircuitBreakerMetrics{
		Name:            cb.config.Name,
		State:           cb.state,
		Failures:        cb.failures,
		Successes:       cb.successes,
		Requests:        cb.requests,
		LastFailureTime: cb.lastFailureTime,
	}
}

// CircuitBreakerMetrics holds metrics for a circuit breaker
type CircuitBreakerMetrics struct {
	Name            string                `json:"name"`
	State           CircuitBreakerState   `json:"state"`
	Failures        int                   `json:"failures"`
	Successes       int                   `json:"successes"`
	Requests        int                   `json:"requests"`
	LastFailureTime time.Time             `json:"last_failure_time"`
}

// CircuitBreakerError represents an error from a circuit breaker
type CircuitBreakerError struct {
	State   CircuitBreakerState
	Message string
}

func (e *CircuitBreakerError) Error() string {
	return e.Message
}

// IsCircuitBreakerError checks if an error is a circuit breaker error
func IsCircuitBreakerError(err error) bool {
	var cbErr *CircuitBreakerError
	return errors.As(err, &cbErr)
}

// CircuitBreakerManager manages multiple circuit breakers
type CircuitBreakerManager struct {
	breakers map[string]*CircuitBreaker
	mu       sync.RWMutex
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager() *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// GetOrCreate gets an existing circuit breaker or creates a new one
func (cbm *CircuitBreakerManager) GetOrCreate(name string, config CircuitBreakerConfig) *CircuitBreaker {
	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	if cb, exists := cbm.breakers[name]; exists {
		return cb
	}

	config.Name = name
	cb := NewCircuitBreaker(config)
	cbm.breakers[name] = cb
	return cb
}

// Get gets an existing circuit breaker
func (cbm *CircuitBreakerManager) Get(name string) (*CircuitBreaker, bool) {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()

	cb, exists := cbm.breakers[name]
	return cb, exists
}

// GetAllMetrics returns metrics for all circuit breakers
func (cbm *CircuitBreakerManager) GetAllMetrics() map[string]CircuitBreakerMetrics {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()

	metrics := make(map[string]CircuitBreakerMetrics)
	for name, cb := range cbm.breakers {
		metrics[name] = cb.GetMetrics()
	}
	return metrics
}

// Reset resets a specific circuit breaker
func (cbm *CircuitBreakerManager) Reset(name string) error {
	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	cb, exists := cbm.breakers[name]
	if !exists {
		return fmt.Errorf("circuit breaker %s not found", name)
	}

	cb.mu.Lock()
	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
	cb.requests = 0
	cb.mu.Unlock()

	return nil
}

// Remove removes a circuit breaker
func (cbm *CircuitBreakerManager) Remove(name string) {
	cbm.mu.Lock()
	defer cbm.mu.Unlock()

	delete(cbm.breakers, name)
}

// List returns names of all circuit breakers
func (cbm *CircuitBreakerManager) List() []string {
	cbm.mu.RLock()
	defer cbm.mu.RUnlock()

	names := make([]string, 0, len(cbm.breakers))
	for name := range cbm.breakers {
		names = append(names, name)
	}
	return names
}