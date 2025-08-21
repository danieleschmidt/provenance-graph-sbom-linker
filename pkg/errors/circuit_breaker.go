package errors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// CircuitBreakerState represents the current state of the circuit breaker
type CircuitBreakerState int

const (
	StateClosed   CircuitBreakerState = iota // Normal operation
	StateOpen                                // Failing fast
	StateHalfOpen                            // Testing if service recovered
)

// CircuitBreakerConfig configures the circuit breaker behavior
type CircuitBreakerConfig struct {
	MaxFailures        int           `yaml:"max_failures"`
	Timeout            time.Duration `yaml:"timeout"`
	MaxRequests        uint32        `yaml:"max_requests"`
	Interval           time.Duration `yaml:"interval"`
	OnStateChange      func(from, to CircuitBreakerState)
	IsSuccessful       func(error) bool
}

// CircuitBreakerCounts holds the statistics of the circuit breaker
type CircuitBreakerCounts struct {
	Requests             uint32
	TotalSuccesses       uint32
	TotalFailures        uint32
	ConsecutiveSuccesses uint32
	ConsecutiveFailures  uint32
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	name        string
	config      CircuitBreakerConfig
	state       CircuitBreakerState
	generation  uint64
	counts      CircuitBreakerCounts
	expiry      time.Time
	logger      *logrus.Logger
	mutex       sync.RWMutex
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(name string, config CircuitBreakerConfig, logger *logrus.Logger) *CircuitBreaker {
	cb := &CircuitBreaker{
		name:   name,
		config: config,
		state:  StateClosed,
		logger: logger,
	}
	
	if cb.config.IsSuccessful == nil {
		cb.config.IsSuccessful = func(err error) bool {
			return err == nil
		}
	}
	
	return cb
}

// Execute wraps the function call with circuit breaker logic
func (cb *CircuitBreaker) Execute(fn func() error) error {
	generation, err := cb.beforeRequest()
	if err != nil {
		return err
	}
	
	defer func() {
		if r := recover(); r != nil {
			cb.afterRequest(generation, fmt.Errorf("panic: %v", r))
			panic(r)
		}
	}()
	
	result := fn()
	cb.afterRequest(generation, result)
	return result
}

// ExecuteWithContext wraps the function call with circuit breaker logic and context
func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, fn func(context.Context) error) error {
	generation, err := cb.beforeRequest()
	if err != nil {
		return err
	}
	
	defer func() {
		if r := recover(); r != nil {
			cb.afterRequest(generation, fmt.Errorf("panic: %v", r))
			panic(r)
		}
	}()
	
	result := fn(ctx)
	cb.afterRequest(generation, result)
	return result
}

// State returns the current state of the circuit breaker
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	now := time.Now()
	state, _ := cb.currentState(now)
	return state
}

// Counts returns the current counts of the circuit breaker
func (cb *CircuitBreaker) Counts() CircuitBreakerCounts {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	return cb.counts
}

// Name returns the name of the circuit breaker
func (cb *CircuitBreaker) Name() string {
	return cb.name
}

// beforeRequest is called before executing the request
func (cb *CircuitBreaker) beforeRequest() (uint64, error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	now := time.Now()
	state, generation := cb.currentState(now)
	
	if state == StateOpen {
		cb.logger.WithFields(logrus.Fields{
			"circuit_breaker": cb.name,
			"state":          "open",
		}).Debug("Circuit breaker is open, failing fast")
		return generation, fmt.Errorf("circuit breaker '%s' is open", cb.name)
	}
	
	if state == StateHalfOpen && cb.counts.Requests >= cb.config.MaxRequests {
		cb.logger.WithFields(logrus.Fields{
			"circuit_breaker": cb.name,
			"state":          "half_open",
			"requests":       cb.counts.Requests,
			"max_requests":   cb.config.MaxRequests,
		}).Debug("Circuit breaker half-open request limit reached")
		return generation, fmt.Errorf("circuit breaker '%s' is half-open and max requests reached", cb.name)
	}
	
	cb.counts.Requests++
	return generation, nil
}

// afterRequest is called after executing the request
func (cb *CircuitBreaker) afterRequest(before uint64, err error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	now := time.Now()
	state, generation := cb.currentState(now)
	
	if generation != before {
		// State changed during request execution
		return
	}
	
	if cb.config.IsSuccessful(err) {
		cb.onSuccess(state, now)
	} else {
		cb.onFailure(state, now)
	}
}

// onSuccess handles successful requests
func (cb *CircuitBreaker) onSuccess(state CircuitBreakerState, now time.Time) {
	cb.counts.TotalSuccesses++
	cb.counts.ConsecutiveSuccesses++
	cb.counts.ConsecutiveFailures = 0
	
	if state == StateHalfOpen {
		cb.logger.WithFields(logrus.Fields{
			"circuit_breaker":        cb.name,
			"consecutive_successes":  cb.counts.ConsecutiveSuccesses,
		}).Debug("Circuit breaker half-open success")
		
		if cb.counts.ConsecutiveSuccesses >= uint32(cb.config.MaxFailures) {
			cb.setState(StateClosed, now)
		}
	}
}

// onFailure handles failed requests
func (cb *CircuitBreaker) onFailure(state CircuitBreakerState, now time.Time) {
	cb.counts.TotalFailures++
	cb.counts.ConsecutiveFailures++
	cb.counts.ConsecutiveSuccesses = 0
	
	if cb.readyToTrip(state) {
		cb.setState(StateOpen, now)
	}
}

// readyToTrip checks if the circuit breaker should trip to open state
func (cb *CircuitBreaker) readyToTrip(state CircuitBreakerState) bool {
	return cb.counts.ConsecutiveFailures >= uint32(cb.config.MaxFailures)
}

// setState changes the state of the circuit breaker
func (cb *CircuitBreaker) setState(state CircuitBreakerState, now time.Time) {
	if cb.state == state {
		return
	}
	
	prev := cb.state
	cb.state = state
	cb.generation++
	
	var expiry time.Time
	switch state {
	case StateClosed:
		expiry = now.Add(cb.config.Interval)
	case StateOpen:
		expiry = now.Add(cb.config.Timeout)
	case StateHalfOpen:
		expiry = now.Add(cb.config.Timeout)
	}
	
	cb.expiry = expiry
	cb.counts = CircuitBreakerCounts{}
	
	cb.logger.WithFields(logrus.Fields{
		"circuit_breaker": cb.name,
		"from_state":     stateToString(prev),
		"to_state":       stateToString(state),
		"expiry":         expiry,
	}).Info("Circuit breaker state changed")
	
	if cb.config.OnStateChange != nil {
		cb.config.OnStateChange(prev, state)
	}
}

// currentState determines the current state considering the expiry time
func (cb *CircuitBreaker) currentState(now time.Time) (CircuitBreakerState, uint64) {
	switch cb.state {
	case StateClosed:
		if !cb.expiry.IsZero() && cb.expiry.Before(now) {
			// Reset counts periodically in closed state
			cb.counts = CircuitBreakerCounts{}
			cb.expiry = now.Add(cb.config.Interval)
		}
	case StateOpen:
		if cb.expiry.Before(now) {
			// Transition from open to half-open
			cb.setState(StateHalfOpen, now)
		}
	}
	
	return cb.state, cb.generation
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	now := time.Now()
	cb.setState(StateClosed, now)
	
	cb.logger.WithFields(logrus.Fields{
		"circuit_breaker": cb.name,
	}).Info("Circuit breaker manually reset")
}

// stateToString converts state to string representation
func stateToString(state CircuitBreakerState) string {
	switch state {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerRegistry manages multiple circuit breakers
type CircuitBreakerRegistry struct {
	breakers map[string]*CircuitBreaker
	mutex    sync.RWMutex
	logger   *logrus.Logger
}

// NewCircuitBreakerRegistry creates a new registry for circuit breakers
func NewCircuitBreakerRegistry(logger *logrus.Logger) *CircuitBreakerRegistry {
	return &CircuitBreakerRegistry{
		breakers: make(map[string]*CircuitBreaker),
		logger:   logger,
	}
}

// GetOrCreate gets an existing circuit breaker or creates a new one
func (cbr *CircuitBreakerRegistry) GetOrCreate(name string, config CircuitBreakerConfig) *CircuitBreaker {
	cbr.mutex.RLock()
	if cb, exists := cbr.breakers[name]; exists {
		cbr.mutex.RUnlock()
		return cb
	}
	cbr.mutex.RUnlock()
	
	cbr.mutex.Lock()
	defer cbr.mutex.Unlock()
	
	// Double-check locking
	if cb, exists := cbr.breakers[name]; exists {
		return cb
	}
	
	cb := NewCircuitBreaker(name, config, cbr.logger)
	cbr.breakers[name] = cb
	
	cbr.logger.WithFields(logrus.Fields{
		"circuit_breaker": name,
		"config":         config,
	}).Info("Created new circuit breaker")
	
	return cb
}

// Get retrieves a circuit breaker by name
func (cbr *CircuitBreakerRegistry) Get(name string) (*CircuitBreaker, bool) {
	cbr.mutex.RLock()
	defer cbr.mutex.RUnlock()
	
	cb, exists := cbr.breakers[name]
	return cb, exists
}

// List returns all registered circuit breakers
func (cbr *CircuitBreakerRegistry) List() map[string]*CircuitBreaker {
	cbr.mutex.RLock()
	defer cbr.mutex.RUnlock()
	
	result := make(map[string]*CircuitBreaker)
	for name, cb := range cbr.breakers {
		result[name] = cb
	}
	
	return result
}

// Remove removes a circuit breaker from the registry
func (cbr *CircuitBreakerRegistry) Remove(name string) {
	cbr.mutex.Lock()
	defer cbr.mutex.Unlock()
	
	delete(cbr.breakers, name)
	
	cbr.logger.WithFields(logrus.Fields{
		"circuit_breaker": name,
	}).Info("Removed circuit breaker from registry")
}

// GetStats returns statistics for all circuit breakers
func (cbr *CircuitBreakerRegistry) GetStats() map[string]interface{} {
	cbr.mutex.RLock()
	defer cbr.mutex.RUnlock()
	
	stats := make(map[string]interface{})
	
	for name, cb := range cbr.breakers {
		stats[name] = map[string]interface{}{
			"state":  stateToString(cb.State()),
			"counts": cb.Counts(),
		}
	}
	
	return stats
}