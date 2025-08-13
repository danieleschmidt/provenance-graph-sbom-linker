package resilience

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int32

const (
	StateClosed CircuitState = iota
	StateHalfOpen
	StateOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateHalfOpen:
		return "HALF_OPEN"
	case StateOpen:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreakerConfig defines configuration for a circuit breaker
type CircuitBreakerConfig struct {
	Name            string        `json:"name"`
	MaxRequests     uint32        `json:"max_requests"`      // Max requests in half-open state
	Interval        time.Duration `json:"interval"`          // Time window for failure counting
	Timeout         time.Duration `json:"timeout"`           // Timeout before trying half-open
	FailureThreshold uint32       `json:"failure_threshold"` // Number of failures to open circuit
	SuccessThreshold uint32       `json:"success_threshold"` // Number of successes to close circuit
	OnStateChange   func(name string, from, to CircuitState) `json:"-"`
}

// DefaultConfig returns a default circuit breaker configuration
func DefaultConfig(name string) CircuitBreakerConfig {
	return CircuitBreakerConfig{
		Name:             name,
		MaxRequests:      10,
		Interval:         10 * time.Second,
		Timeout:          60 * time.Second,
		FailureThreshold: 5,
		SuccessThreshold: 3,
	}
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config       CircuitBreakerConfig
	mutex        sync.RWMutex
	state        CircuitState
	counts       *Counts
	generation   uint64
	expiry       time.Time
}

// Counts tracks request statistics
type Counts struct {
	Requests             uint32
	TotalSuccesses       uint32
	TotalFailures        uint32
	ConsecutiveSuccesses uint32
	ConsecutiveFailures  uint32
}

// CircuitBreakerError represents errors from circuit breaker operations
type CircuitBreakerError struct {
	State   CircuitState
	Message string
}

func (e *CircuitBreakerError) Error() string {
	return fmt.Sprintf("circuit breaker %s: %s", e.State, e.Message)
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	cb := &CircuitBreaker{
		config:     config,
		state:      StateClosed,
		counts:     &Counts{},
		generation: 0,
		expiry:     time.Now(),
	}
	
	return cb
}

// Execute executes the given function within the circuit breaker
func (cb *CircuitBreaker) Execute(fn func() error) error {
	generation, err := cb.beforeRequest()
	if err != nil {
		return err
	}
	
	defer func() {
		if r := recover(); r != nil {
			cb.afterRequest(generation, false)
			panic(r)
		}
	}()
	
	result := fn()
	cb.afterRequest(generation, result == nil)
	return result
}

// ExecuteWithContext executes the given function with context within the circuit breaker
func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, fn func(context.Context) error) error {
	generation, err := cb.beforeRequest()
	if err != nil {
		return err
	}
	
	defer func() {
		if r := recover(); r != nil {
			cb.afterRequest(generation, false)
			panic(r)
		}
	}()
	
	// Create a channel to handle function execution
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic: %v", r)
			}
		}()
		done <- fn(ctx)
	}()
	
	// Wait for either completion or context cancellation
	select {
	case result := <-done:
		cb.afterRequest(generation, result == nil)
		return result
	case <-ctx.Done():
		cb.afterRequest(generation, false)
		return ctx.Err()
	}
}

// State returns the current state of the circuit breaker
func (cb *CircuitBreaker) State() CircuitState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	now := time.Now()
	state, _ := cb.currentState(now)
	return state
}

// Counts returns the current counts
func (cb *CircuitBreaker) Counts() Counts {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	return *cb.counts
}

// Name returns the circuit breaker name
func (cb *CircuitBreaker) Name() string {
	return cb.config.Name
}

// beforeRequest is called before making a request
func (cb *CircuitBreaker) beforeRequest() (uint64, error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	now := time.Now()
	state, generation := cb.currentState(now)
	
	if state == StateOpen {
		return generation, &CircuitBreakerError{
			State:   StateOpen,
			Message: "circuit breaker is open",
		}
	}
	
	if state == StateHalfOpen && cb.counts.Requests >= cb.config.MaxRequests {
		return generation, &CircuitBreakerError{
			State:   StateHalfOpen,
			Message: "too many requests in half-open state",
		}
	}
	
	cb.counts.Requests++
	return generation, nil
}

// afterRequest is called after making a request
func (cb *CircuitBreaker) afterRequest(before uint64, success bool) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	now := time.Now()
	state, generation := cb.currentState(now)
	
	// Ignore if this request was from a previous generation
	if generation != before {
		return
	}
	
	if success {
		cb.onSuccess(state, now)
	} else {
		cb.onFailure(state, now)
	}
}

// onSuccess handles successful requests
func (cb *CircuitBreaker) onSuccess(state CircuitState, now time.Time) {
	cb.counts.TotalSuccesses++
	cb.counts.ConsecutiveSuccesses++
	cb.counts.ConsecutiveFailures = 0
	
	if state == StateHalfOpen && cb.counts.ConsecutiveSuccesses >= cb.config.SuccessThreshold {
		cb.setState(StateClosed, now)
	}
}

// onFailure handles failed requests
func (cb *CircuitBreaker) onFailure(state CircuitState, now time.Time) {
	cb.counts.TotalFailures++
	cb.counts.ConsecutiveFailures++
	cb.counts.ConsecutiveSuccesses = 0
	
	if state == StateClosed && cb.counts.ConsecutiveFailures >= cb.config.FailureThreshold {
		cb.setState(StateOpen, now)
	} else if state == StateHalfOpen {
		cb.setState(StateOpen, now)
	}
}

// currentState returns the current state and generation
func (cb *CircuitBreaker) currentState(now time.Time) (CircuitState, uint64) {
	switch cb.state {
	case StateClosed:
		if !cb.expiry.IsZero() && cb.expiry.Before(now) {
			cb.toNewGeneration(now)
		}
	case StateOpen:
		if cb.expiry.Before(now) {
			cb.setState(StateHalfOpen, now)
		}
	}
	
	return cb.state, cb.generation
}

// setState changes the circuit breaker state
func (cb *CircuitBreaker) setState(state CircuitState, now time.Time) {
	if cb.state == state {
		return
	}
	
	prev := cb.state
	cb.state = state
	cb.toNewGeneration(now)
	
	// Call state change callback if configured
	if cb.config.OnStateChange != nil {
		go cb.config.OnStateChange(cb.config.Name, prev, state)
	}
}

// toNewGeneration starts a new generation
func (cb *CircuitBreaker) toNewGeneration(now time.Time) {
	cb.generation++
	cb.counts = &Counts{}
	
	var zero time.Time
	switch cb.state {
	case StateClosed:
		if cb.config.Interval == 0 {
			cb.expiry = zero
		} else {
			cb.expiry = now.Add(cb.config.Interval)
		}
	case StateOpen:
		cb.expiry = now.Add(cb.config.Timeout)
	default: // StateHalfOpen
		cb.expiry = zero
	}
}

// CircuitBreakerManager manages multiple circuit breakers
type CircuitBreakerManager struct {
	breakers map[string]*CircuitBreaker
	mutex    sync.RWMutex
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager() *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// GetCircuitBreaker gets or creates a circuit breaker
func (cbm *CircuitBreakerManager) GetCircuitBreaker(name string, config ...CircuitBreakerConfig) *CircuitBreaker {
	cbm.mutex.RLock()
	if cb, exists := cbm.breakers[name]; exists {
		cbm.mutex.RUnlock()
		return cb
	}
	cbm.mutex.RUnlock()
	
	cbm.mutex.Lock()
	defer cbm.mutex.Unlock()
	
	// Double-check pattern
	if cb, exists := cbm.breakers[name]; exists {
		return cb
	}
	
	var cbConfig CircuitBreakerConfig
	if len(config) > 0 {
		cbConfig = config[0]
		cbConfig.Name = name
	} else {
		cbConfig = DefaultConfig(name)
	}
	
	cb := NewCircuitBreaker(cbConfig)
	cbm.breakers[name] = cb
	return cb
}

// GetAllBreakers returns all circuit breakers
func (cbm *CircuitBreakerManager) GetAllBreakers() map[string]*CircuitBreaker {
	cbm.mutex.RLock()
	defer cbm.mutex.RUnlock()
	
	result := make(map[string]*CircuitBreaker)
	for name, cb := range cbm.breakers {
		result[name] = cb
	}
	return result
}

// RemoveCircuitBreaker removes a circuit breaker
func (cbm *CircuitBreakerManager) RemoveCircuitBreaker(name string) {
	cbm.mutex.Lock()
	defer cbm.mutex.Unlock()
	
	delete(cbm.breakers, name)
}

// Global circuit breaker manager instance
var globalManager = NewCircuitBreakerManager()

// GetCircuitBreaker gets a circuit breaker from the global manager
func GetCircuitBreaker(name string, config ...CircuitBreakerConfig) *CircuitBreaker {
	return globalManager.GetCircuitBreaker(name, config...)
}

// Retry configuration for resilient operations
type RetryConfig struct {
	MaxRetries    int           `json:"max_retries"`
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	Jitter        bool          `json:"jitter"`
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:    3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
	}
}

// RetryWithCircuitBreaker combines retry logic with circuit breaker
func RetryWithCircuitBreaker(ctx context.Context, cbName string, retryConfig RetryConfig, fn func() error) error {
	cb := GetCircuitBreaker(cbName)
	
	var lastErr error
	for attempt := 0; attempt <= retryConfig.MaxRetries; attempt++ {
		err := cb.ExecuteWithContext(ctx, func(context.Context) error {
			return fn()
		})
		
		if err == nil {
			return nil
		}
		
		lastErr = err
		
		// Don't retry if circuit breaker is open
		if cbErr, ok := err.(*CircuitBreakerError); ok && cbErr.State == StateOpen {
			return err
		}
		
		// Don't retry on context cancellation
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		
		// Calculate delay for next attempt
		if attempt < retryConfig.MaxRetries {
			delay := calculateDelay(attempt, retryConfig)
			select {
			case <-time.After(delay):
				// Continue to next attempt
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	
	return lastErr
}

// calculateDelay calculates the delay for the next retry attempt
func calculateDelay(attempt int, config RetryConfig) time.Duration {
	delay := float64(config.InitialDelay) * pow(config.BackoffFactor, float64(attempt))
	
	if delay > float64(config.MaxDelay) {
		delay = float64(config.MaxDelay)
	}
	
	if config.Jitter {
		// Add up to 10% jitter
		jitter := delay * 0.1 * float64(time.Now().UnixNano()%1000)/1000.0
		delay += jitter
	}
	
	return time.Duration(delay)
}

// pow is a simple power function for floats
func pow(base, exp float64) float64 {
	if exp == 0 {
		return 1
	}
	result := base
	for i := 1; i < int(exp); i++ {
		result *= base
	}
	return result
}

// HealthCheck represents the health status of a service
type HealthCheck struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details,omitempty"`
	Duration  time.Duration `json:"duration"`
}

// HealthChecker interface for health checking
type HealthChecker interface {
	Check(ctx context.Context) HealthCheck
}

// SimpleHealthChecker implements basic health checking
type SimpleHealthChecker struct {
	name string
	fn   func(context.Context) error
}

// NewSimpleHealthChecker creates a new simple health checker
func NewSimpleHealthChecker(name string, fn func(context.Context) error) *SimpleHealthChecker {
	return &SimpleHealthChecker{
		name: name,
		fn:   fn,
	}
}

// Check performs the health check
func (shc *SimpleHealthChecker) Check(ctx context.Context) HealthCheck {
	start := time.Now()
	err := shc.fn(ctx)
	duration := time.Since(start)
	
	status := "healthy"
	details := ""
	if err != nil {
		status = "unhealthy"
		details = err.Error()
	}
	
	return HealthCheck{
		Name:      shc.name,
		Status:    status,
		Timestamp: time.Now(),
		Details:   details,
		Duration:  duration,
	}
}