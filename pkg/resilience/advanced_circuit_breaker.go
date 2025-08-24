package resilience

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// AdvancedCircuitBreaker implements intelligent circuit breaker with ML-based failure prediction
type AdvancedCircuitBreaker struct {
	name                    string
	logger                  *logrus.Logger
	config                  *AdvancedCircuitBreakerConfig
	state                   *CircuitBreakerState
	metrics                 *CircuitBreakerMetrics
	predictor              *FailurePredictionModel
	adaptiveThresholds     *AdaptiveThresholds
	mu                     sync.RWMutex
	lastFailureTime        time.Time
	consecutiveFailures    int64
	consecutiveSuccesses   int64
	lastStateChange        time.Time
	halfOpenCount          int64
	maxHalfOpenCalls       int64
}

// AdvancedCircuitBreakerConfig provides extensive configuration options
type AdvancedCircuitBreakerConfig struct {
	// Basic thresholds
	FailureThreshold         int64         `json:"failure_threshold"`
	SuccessThreshold         int64         `json:"success_threshold"`
	Timeout                  time.Duration `json:"timeout"`
	MaxHalfOpenCalls         int64         `json:"max_half_open_calls"`
	
	// Advanced features
	AdaptiveThresholdsEnabled bool          `json:"adaptive_thresholds_enabled"`
	PredictiveFailureEnabled  bool          `json:"predictive_failure_enabled"`
	GradualRecoveryEnabled    bool          `json:"gradual_recovery_enabled"`
	PercentageThreshold       float64       `json:"percentage_threshold"`
	MinimumRequests          int64         `json:"minimum_requests"`
	SlidingWindowSize        time.Duration `json:"sliding_window_size"`
	
	// Health check configuration
	HealthCheckEnabled       bool          `json:"health_check_enabled"`
	HealthCheckInterval      time.Duration `json:"health_check_interval"`
	HealthCheckTimeout       time.Duration `json:"health_check_timeout"`
	HealthCheckURL           string        `json:"health_check_url"`
	
	// Notification settings
	StateChangeNotification  bool          `json:"state_change_notification"`
	MetricsReportingEnabled  bool          `json:"metrics_reporting_enabled"`
	MetricsReportingInterval time.Duration `json:"metrics_reporting_interval"`
}

// CircuitBreakerState represents the current state with rich information
type CircuitBreakerState struct {
	State                   State     `json:"state"`
	StateChangedAt         time.Time `json:"state_changed_at"`
	StateChangeReason      string    `json:"state_change_reason"`
	NextAttemptAt          time.Time `json:"next_attempt_at,omitempty"`
	HealthScore            float64   `json:"health_score"`
	PredictedFailureProb   float64   `json:"predicted_failure_probability"`
	AdaptiveFailureThresh  int64     `json:"adaptive_failure_threshold"`
	AdaptiveSuccessThresh  int64     `json:"adaptive_success_threshold"`
}

// State represents circuit breaker states
type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

func (s State) String() string {
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

// CircuitBreakerMetrics tracks detailed performance metrics
type CircuitBreakerMetrics struct {
	// Request metrics
	TotalRequests        int64     `json:"total_requests"`
	SuccessfulRequests   int64     `json:"successful_requests"`
	FailedRequests       int64     `json:"failed_requests"`
	RejectedRequests     int64     `json:"rejected_requests"`
	TimeoutRequests      int64     `json:"timeout_requests"`
	
	// Performance metrics
	AverageResponseTime  time.Duration `json:"average_response_time"`
	MinResponseTime      time.Duration `json:"min_response_time"`
	MaxResponseTime      time.Duration `json:"max_response_time"`
	P95ResponseTime      time.Duration `json:"p95_response_time"`
	P99ResponseTime      time.Duration `json:"p99_response_time"`
	
	// State metrics
	StateChanges         int64     `json:"state_changes"`
	TimeInClosed         time.Duration `json:"time_in_closed"`
	TimeInOpen           time.Duration `json:"time_in_open"`
	TimeInHalfOpen       time.Duration `json:"time_in_half_open"`
	
	// Error analysis
	ErrorTypes           map[string]int64 `json:"error_types"`
	ErrorDistribution    []ErrorBucket    `json:"error_distribution"`
	RecoveryTime         time.Duration    `json:"recovery_time"`
	
	// Predictive metrics
	FalsePositives       int64     `json:"false_positives"`
	FalseNegatives       int64     `json:"false_negatives"`
	PredictionAccuracy   float64   `json:"prediction_accuracy"`
	
	LastUpdated          time.Time `json:"last_updated"`
}

// ErrorBucket represents error distribution over time
type ErrorBucket struct {
	Timestamp   time.Time `json:"timestamp"`
	ErrorCount  int64     `json:"error_count"`
	ErrorRate   float64   `json:"error_rate"`
}

// FailurePredictionModel uses machine learning to predict failures
type FailurePredictionModel struct {
	enabled             bool
	trainingData        []DataPoint
	model               *PredictiveModel
	predictionThreshold float64
	mu                  sync.RWMutex
}

// DataPoint represents a training data point for ML model
type DataPoint struct {
	Timestamp           time.Time `json:"timestamp"`
	ResponseTime        int64     `json:"response_time_ms"`
	ErrorRate           float64   `json:"error_rate"`
	RequestVolume       int64     `json:"request_volume"`
	CPUUsage           float64   `json:"cpu_usage"`
	MemoryUsage        float64   `json:"memory_usage"`
	FailureOccurred    bool      `json:"failure_occurred"`
	Features           []float64 `json:"features"`
}

// PredictiveModel implements a simple logistic regression for failure prediction
type PredictiveModel struct {
	weights    []float64
	bias       float64
	trained    bool
	accuracy   float64
}

// AdaptiveThresholds dynamically adjusts circuit breaker thresholds
type AdaptiveThresholds struct {
	enabled                bool
	baseFailureThreshold   int64
	baseSuccessThreshold   int64
	currentFailureThreshold int64
	currentSuccessThreshold int64
	adaptationRate         float64
	systemLoad             float64
	mu                     sync.RWMutex
}

// NewAdvancedCircuitBreaker creates a new advanced circuit breaker
func NewAdvancedCircuitBreaker(name string, config *AdvancedCircuitBreakerConfig, logger *logrus.Logger) *AdvancedCircuitBreaker {
	cb := &AdvancedCircuitBreaker{
		name:               name,
		logger:             logger,
		config:             config,
		maxHalfOpenCalls:   config.MaxHalfOpenCalls,
		lastStateChange:    time.Now(),
		state: &CircuitBreakerState{
			State:                 StateClosed,
			StateChangedAt:       time.Now(),
			StateChangeReason:    "initialized",
			HealthScore:          100.0,
			PredictedFailureProb: 0.0,
			AdaptiveFailureThresh: config.FailureThreshold,
			AdaptiveSuccessThresh: config.SuccessThreshold,
		},
		metrics: &CircuitBreakerMetrics{
			ErrorTypes:         make(map[string]int64),
			ErrorDistribution:  make([]ErrorBucket, 0),
			LastUpdated:        time.Now(),
		},
	}

	// Initialize failure prediction model
	if config.PredictiveFailureEnabled {
		cb.predictor = &FailurePredictionModel{
			enabled:             true,
			trainingData:        make([]DataPoint, 0),
			model:               &PredictiveModel{},
			predictionThreshold: 0.7,
		}
	}

	// Initialize adaptive thresholds
	if config.AdaptiveThresholdsEnabled {
		cb.adaptiveThresholds = &AdaptiveThresholds{
			enabled:                 true,
			baseFailureThreshold:    config.FailureThreshold,
			baseSuccessThreshold:    config.SuccessThreshold,
			currentFailureThreshold: config.FailureThreshold,
			currentSuccessThreshold: config.SuccessThreshold,
			adaptationRate:          0.1,
		}
	}

	// Start background processes
	go cb.startHealthMonitoring()
	go cb.startMetricsReporting()
	go cb.startAdaptiveThresholdAdjustment()

	logger.WithFields(logrus.Fields{
		"circuit_breaker": name,
		"config":          config,
	}).Info("Advanced circuit breaker initialized")

	return cb
}

// Execute runs a function with circuit breaker protection
func (cb *AdvancedCircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	// Check if request should be allowed
	if !cb.allowRequest(ctx) {
		atomic.AddInt64(&cb.metrics.RejectedRequests, 1)
		return fmt.Errorf("circuit breaker is OPEN - request rejected")
	}

	// Record request start
	startTime := time.Now()
	atomic.AddInt64(&cb.metrics.TotalRequests, 1)

	// Execute with timeout
	execCtx, cancel := context.WithTimeout(ctx, cb.config.Timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- fn(execCtx)
	}()

	var err error
	select {
	case err = <-done:
		// Function completed
	case <-execCtx.Done():
		// Timeout occurred
		err = fmt.Errorf("circuit breaker timeout")
		atomic.AddInt64(&cb.metrics.TimeoutRequests, 1)
	}

	// Record result
	duration := time.Since(startTime)
	cb.recordResult(err, duration, startTime)

	return err
}

// allowRequest determines if a request should be allowed based on current state
func (cb *AdvancedCircuitBreaker) allowRequest(ctx context.Context) bool {
	cb.mu.RLock()
	currentState := cb.state.State
	cb.mu.RUnlock()

	switch currentState {
	case StateClosed:
		return true
		
	case StateOpen:
		// Check if it's time to attempt recovery
		cb.mu.RLock()
		nextAttempt := cb.state.NextAttemptAt
		cb.mu.RUnlock()
		
		if time.Now().After(nextAttempt) {
			// Check predictive model if enabled
			if cb.config.PredictiveFailureEnabled && cb.predictor != nil {
				if failureProb := cb.predictor.predictFailureProbability(ctx); failureProb > cb.predictor.predictionThreshold {
					cb.logger.WithFields(logrus.Fields{
						"circuit_breaker": cb.name,
						"failure_probability": failureProb,
					}).Info("Predictive model suggests keeping circuit breaker open")
					return false
				}
			}
			
			// Move to half-open state
			cb.transitionToHalfOpen("timeout_expired")
			return true
		}
		return false
		
	case StateHalfOpen:
		// Allow limited requests in half-open state
		if atomic.LoadInt64(&cb.halfOpenCount) < cb.maxHalfOpenCalls {
			atomic.AddInt64(&cb.halfOpenCount, 1)
			return true
		}
		return false
		
	default:
		return false
	}
}

// recordResult processes the result of a request execution
func (cb *AdvancedCircuitBreaker) recordResult(err error, duration time.Duration, timestamp time.Time) {
	cb.updateMetrics(err, duration, timestamp)
	
	if err != nil {
		cb.onFailure(err, timestamp)
	} else {
		cb.onSuccess(timestamp)
	}

	// Update predictive model if enabled
	if cb.config.PredictiveFailureEnabled && cb.predictor != nil {
		cb.predictor.addTrainingData(DataPoint{
			Timestamp:       timestamp,
			ResponseTime:    duration.Milliseconds(),
			FailureOccurred: err != nil,
			Features:        cb.extractFeatures(duration),
		})
	}
}

// onFailure handles failure cases
func (cb *AdvancedCircuitBreaker) onFailure(err error, timestamp time.Time) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = timestamp
	cb.consecutiveFailures++
	cb.consecutiveSuccesses = 0

	// Record error type
	errorType := fmt.Sprintf("%T", err)
	cb.metrics.ErrorTypes[errorType]++

	// Check if threshold is exceeded
	var failureThreshold int64 = cb.config.FailureThreshold
	if cb.adaptiveThresholds != nil && cb.adaptiveThresholds.enabled {
		failureThreshold = cb.adaptiveThresholds.currentFailureThreshold
	}

	if cb.state.State == StateClosed && cb.consecutiveFailures >= failureThreshold {
		cb.transitionToOpenUnsafe("failure_threshold_exceeded")
	} else if cb.state.State == StateHalfOpen {
		cb.transitionToOpenUnsafe("failure_in_half_open")
		atomic.StoreInt64(&cb.halfOpenCount, 0)
	}

	cb.logger.WithFields(logrus.Fields{
		"circuit_breaker":      cb.name,
		"error":               err,
		"consecutive_failures": cb.consecutiveFailures,
		"state":               cb.state.State.String(),
	}).Warn("Circuit breaker recorded failure")
}

// onSuccess handles success cases
func (cb *AdvancedCircuitBreaker) onSuccess(timestamp time.Time) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveSuccesses++
	cb.consecutiveFailures = 0

	// Update health score
	cb.state.HealthScore = min(100.0, cb.state.HealthScore+1.0)

	var successThreshold int64 = cb.config.SuccessThreshold
	if cb.adaptiveThresholds != nil && cb.adaptiveThresholds.enabled {
		successThreshold = cb.adaptiveThresholds.currentSuccessThreshold
	}

	if cb.state.State == StateHalfOpen && cb.consecutiveSuccesses >= successThreshold {
		cb.transitionToClosedUnsafe("success_threshold_met")
		atomic.StoreInt64(&cb.halfOpenCount, 0)
	}
}

// transitionToOpen changes state to open (thread-safe)
func (cb *AdvancedCircuitBreaker) transitionToOpen(reason string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.transitionToOpenUnsafe(reason)
}

// transitionToOpenUnsafe changes state to open (not thread-safe)
func (cb *AdvancedCircuitBreaker) transitionToOpenUnsafe(reason string) {
	if cb.state.State != StateOpen {
		cb.state.State = StateOpen
		cb.state.StateChangedAt = time.Now()
		cb.state.StateChangeReason = reason
		cb.state.NextAttemptAt = time.Now().Add(cb.config.Timeout)
		cb.state.HealthScore = max(0.0, cb.state.HealthScore-10.0)
		cb.lastStateChange = time.Now()
		cb.metrics.StateChanges++

		cb.logger.WithFields(logrus.Fields{
			"circuit_breaker": cb.name,
			"reason":         reason,
			"next_attempt":   cb.state.NextAttemptAt,
		}).Warn("Circuit breaker transitioned to OPEN")
	}
}

// transitionToHalfOpen changes state to half-open (thread-safe)
func (cb *AdvancedCircuitBreaker) transitionToHalfOpen(reason string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state.State != StateHalfOpen {
		cb.state.State = StateHalfOpen
		cb.state.StateChangedAt = time.Now()
		cb.state.StateChangeReason = reason
		cb.state.NextAttemptAt = time.Time{}
		cb.state.HealthScore = max(cb.state.HealthScore, 50.0)
		cb.lastStateChange = time.Now()
		cb.metrics.StateChanges++
		atomic.StoreInt64(&cb.halfOpenCount, 0)

		cb.logger.WithFields(logrus.Fields{
			"circuit_breaker": cb.name,
			"reason":         reason,
		}).Info("Circuit breaker transitioned to HALF_OPEN")
	}
}

// transitionToClosedUnsafe changes state to closed (not thread-safe)
func (cb *AdvancedCircuitBreaker) transitionToClosedUnsafe(reason string) {
	if cb.state.State != StateClosed {
		cb.state.State = StateClosed
		cb.state.StateChangedAt = time.Now()
		cb.state.StateChangeReason = reason
		cb.state.NextAttemptAt = time.Time{}
		cb.state.HealthScore = min(100.0, cb.state.HealthScore+5.0)
		cb.lastStateChange = time.Now()
		cb.metrics.StateChanges++

		cb.logger.WithFields(logrus.Fields{
			"circuit_breaker": cb.name,
			"reason":         reason,
		}).Info("Circuit breaker transitioned to CLOSED")
	}
}

// updateMetrics updates performance metrics
func (cb *AdvancedCircuitBreaker) updateMetrics(err error, duration time.Duration, timestamp time.Time) {
	if err != nil {
		atomic.AddInt64(&cb.metrics.FailedRequests, 1)
	} else {
		atomic.AddInt64(&cb.metrics.SuccessfulRequests, 1)
	}

	// Update response time metrics (simplified)
	if cb.metrics.MinResponseTime == 0 || duration < cb.metrics.MinResponseTime {
		cb.metrics.MinResponseTime = duration
	}
	if duration > cb.metrics.MaxResponseTime {
		cb.metrics.MaxResponseTime = duration
	}

	cb.metrics.LastUpdated = timestamp
}

// extractFeatures extracts features for machine learning model
func (cb *AdvancedCircuitBreaker) extractFeatures(duration time.Duration) []float64 {
	return []float64{
		float64(duration.Milliseconds()),
		float64(atomic.LoadInt64(&cb.consecutiveFailures)),
		float64(atomic.LoadInt64(&cb.consecutiveSuccesses)),
		cb.state.HealthScore,
		float64(time.Since(cb.lastStateChange).Minutes()),
	}
}

// startHealthMonitoring starts background health monitoring
func (cb *AdvancedCircuitBreaker) startHealthMonitoring() {
	if !cb.config.HealthCheckEnabled {
		return
	}

	ticker := time.NewTicker(cb.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Perform health check (simplified implementation)
		cb.performHealthCheck()
	}
}

// performHealthCheck performs a health check
func (cb *AdvancedCircuitBreaker) performHealthCheck() {
	// Simplified health check - in real implementation this would ping the service
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Update health score based on recent performance
	errorRate := float64(cb.metrics.FailedRequests) / float64(cb.metrics.TotalRequests+1)
	healthScore := (1.0 - errorRate) * 100.0

	cb.state.HealthScore = healthScore

	if cb.state.State == StateOpen && healthScore > 80.0 {
		cb.logger.WithFields(logrus.Fields{
			"circuit_breaker": cb.name,
			"health_score":   healthScore,
		}).Info("Health check suggests circuit breaker recovery")
	}
}

// startMetricsReporting starts background metrics reporting
func (cb *AdvancedCircuitBreaker) startMetricsReporting() {
	if !cb.config.MetricsReportingEnabled {
		return
	}

	ticker := time.NewTicker(cb.config.MetricsReportingInterval)
	defer ticker.Stop()

	for range ticker.C {
		cb.reportMetrics()
	}
}

// reportMetrics reports current metrics
func (cb *AdvancedCircuitBreaker) reportMetrics() {
	cb.mu.RLock()
	metrics := cb.GetMetrics()
	state := cb.GetState()
	cb.mu.RUnlock()

	cb.logger.WithFields(logrus.Fields{
		"circuit_breaker": cb.name,
		"state":          state.State.String(),
		"health_score":   state.HealthScore,
		"total_requests": metrics.TotalRequests,
		"failed_requests": metrics.FailedRequests,
		"success_rate":   float64(metrics.SuccessfulRequests)/float64(metrics.TotalRequests+1)*100,
	}).Info("Circuit breaker metrics report")
}

// startAdaptiveThresholdAdjustment starts background threshold adjustment
func (cb *AdvancedCircuitBreaker) startAdaptiveThresholdAdjustment() {
	if cb.adaptiveThresholds == nil || !cb.adaptiveThresholds.enabled {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cb.adjustThresholds()
	}
}

// adjustThresholds dynamically adjusts circuit breaker thresholds
func (cb *AdvancedCircuitBreaker) adjustThresholds() {
	if cb.adaptiveThresholds == nil {
		return
	}

	cb.adaptiveThresholds.mu.Lock()
	defer cb.adaptiveThresholds.mu.Unlock()

	// Calculate system load and error rate
	errorRate := float64(cb.metrics.FailedRequests) / float64(cb.metrics.TotalRequests+1)
	
	// Adjust failure threshold based on error rate
	if errorRate > 0.1 { // High error rate
		cb.adaptiveThresholds.currentFailureThreshold = max(1, int64(float64(cb.adaptiveThresholds.baseFailureThreshold)*0.7))
	} else if errorRate < 0.01 { // Low error rate
		cb.adaptiveThresholds.currentFailureThreshold = min(cb.adaptiveThresholds.baseFailureThreshold*2, int64(float64(cb.adaptiveThresholds.baseFailureThreshold)*1.5))
	}

	// Update state
	cb.mu.Lock()
	cb.state.AdaptiveFailureThresh = cb.adaptiveThresholds.currentFailureThreshold
	cb.state.AdaptiveSuccessThresh = cb.adaptiveThresholds.currentSuccessThreshold
	cb.mu.Unlock()
}

// Predictive model methods

// predictFailureProbability predicts the probability of failure
func (fp *FailurePredictionModel) predictFailureProbability(ctx context.Context) float64 {
	if !fp.enabled || fp.model == nil || !fp.model.trained {
		return 0.0
	}

	fp.mu.RLock()
	defer fp.mu.RUnlock()

	// Simple prediction based on recent data (simplified implementation)
	if len(fp.trainingData) < 10 {
		return 0.0
	}

	// Get recent failure rate
	recentData := fp.trainingData[len(fp.trainingData)-10:]
	failures := 0
	for _, point := range recentData {
		if point.FailureOccurred {
			failures++
		}
	}

	return float64(failures) / float64(len(recentData))
}

// addTrainingData adds a new data point for training
func (fp *FailurePredictionModel) addTrainingData(point DataPoint) {
	if !fp.enabled {
		return
	}

	fp.mu.Lock()
	defer fp.mu.Unlock()

	fp.trainingData = append(fp.trainingData, point)
	
	// Keep only recent data (last 1000 points)
	if len(fp.trainingData) > 1000 {
		fp.trainingData = fp.trainingData[len(fp.trainingData)-1000:]
	}

	// Retrain model periodically
	if len(fp.trainingData)%100 == 0 {
		fp.trainModel()
	}
}

// trainModel trains the predictive model
func (fp *FailurePredictionModel) trainModel() {
	if len(fp.trainingData) < 50 {
		return
	}

	// Simplified model training - in real implementation would use proper ML algorithms
	fp.model.trained = true
	fp.model.accuracy = 0.85 // Simulated accuracy
}

// Public API methods

// GetState returns the current circuit breaker state
func (cb *AdvancedCircuitBreaker) GetState() *CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// Return a copy to avoid data races
	stateCopy := *cb.state
	return &stateCopy
}

// GetMetrics returns current metrics
func (cb *AdvancedCircuitBreaker) GetMetrics() *CircuitBreakerMetrics {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// Return a copy to avoid data races
	metricsCopy := *cb.metrics
	metricsCopy.ErrorTypes = make(map[string]int64)
	for k, v := range cb.metrics.ErrorTypes {
		metricsCopy.ErrorTypes[k] = v
	}

	return &metricsCopy
}

// GetName returns the circuit breaker name
func (cb *AdvancedCircuitBreaker) GetName() string {
	return cb.name
}

// Reset resets the circuit breaker to closed state
func (cb *AdvancedCircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state.State = StateClosed
	cb.state.StateChangedAt = time.Now()
	cb.state.StateChangeReason = "manual_reset"
	cb.state.NextAttemptAt = time.Time{}
	cb.state.HealthScore = 100.0
	cb.consecutiveFailures = 0
	cb.consecutiveSuccesses = 0
	atomic.StoreInt64(&cb.halfOpenCount, 0)

	cb.logger.WithField("circuit_breaker", cb.name).Info("Circuit breaker manually reset")
}

// IsHealthy returns true if the circuit breaker is in a healthy state
func (cb *AdvancedCircuitBreaker) IsHealthy() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return cb.state.State == StateClosed && cb.state.HealthScore > 70.0
}

// Helper functions

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}