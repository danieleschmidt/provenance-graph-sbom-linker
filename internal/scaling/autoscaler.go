package scaling

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ScalingDirection indicates whether to scale up or down
type ScalingDirection string

const (
	ScaleUp   ScalingDirection = "up"
	ScaleDown ScalingDirection = "down"
	ScaleNone ScalingDirection = "none"
)

// ScalingPolicy defines when and how to scale
type ScalingPolicy struct {
	Name                string            `json:"name"`
	MetricName          string            `json:"metric_name"`
	TargetValue         float64           `json:"target_value"`
	Tolerance           float64           `json:"tolerance"`
	ScaleUpThreshold    float64           `json:"scale_up_threshold"`
	ScaleDownThreshold  float64           `json:"scale_down_threshold"`
	MinInstances        int               `json:"min_instances"`
	MaxInstances        int               `json:"max_instances"`
	ScaleUpStep         int               `json:"scale_up_step"`
	ScaleDownStep       int               `json:"scale_down_step"`
	Cooldown            time.Duration     `json:"cooldown"`
	EvaluationPeriod    time.Duration     `json:"evaluation_period"`
	DataPointsRequired  int               `json:"data_points_required"`
	Enabled             bool              `json:"enabled"`
	Constraints         map[string]float64 `json:"constraints,omitempty"`
}

// ScalingMetric represents a metric used for scaling decisions
type ScalingMetric struct {
	Name      string                 `json:"name"`
	Value     float64                `json:"value"`
	Unit      string                 `json:"unit"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Labels    map[string]string      `json:"labels,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ScalingDecision represents a scaling decision
type ScalingDecision struct {
	PolicyName      string           `json:"policy_name"`
	Direction       ScalingDirection `json:"direction"`
	CurrentReplicas int              `json:"current_replicas"`
	DesiredReplicas int              `json:"desired_replicas"`
	Reason          string           `json:"reason"`
	Confidence      float64          `json:"confidence"` // 0.0-1.0
	Timestamp       time.Time        `json:"timestamp"`
	MetricValue     float64          `json:"metric_value"`
	TargetValue     float64          `json:"target_value"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ScalingEvent represents a completed scaling action
type ScalingEvent struct {
	ID              string           `json:"id"`
	PolicyName      string           `json:"policy_name"`
	Direction       ScalingDirection `json:"direction"`
	FromReplicas    int              `json:"from_replicas"`
	ToReplicas      int              `json:"to_replicas"`
	Reason          string           `json:"reason"`
	StartTime       time.Time        `json:"start_time"`
	EndTime         time.Time        `json:"end_time"`
	Duration        time.Duration    `json:"duration"`
	Success         bool             `json:"success"`
	Error           string           `json:"error,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ScalingTarget represents something that can be scaled
type ScalingTarget interface {
	Name() string
	CurrentReplicas() int
	Scale(ctx context.Context, replicas int) error
	IsHealthy() bool
}

// AutoScaler provides intelligent automatic scaling
type AutoScaler struct {
	policies      map[string]*ScalingPolicy
	targets       map[string]ScalingTarget
	metrics       map[string][]ScalingMetric
	events        []ScalingEvent
	lastDecisions map[string]time.Time
	mutex         sync.RWMutex
	logger        *logrus.Logger
	
	// Configuration
	metricsWindow     time.Duration
	evaluationInterval time.Duration
	maxEvents         int
	
	// State
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	
	// Statistics
	totalScalingEvents int64
	successfulScales   int64
	failedScales       int64
}

// AutoScalerConfig configures the autoscaler
type AutoScalerConfig struct {
	MetricsWindow       time.Duration
	EvaluationInterval  time.Duration
	MaxEvents          int
}

// NewAutoScaler creates a new autoscaler
func NewAutoScaler(config AutoScalerConfig, logger *logrus.Logger) *AutoScaler {
	if logger == nil {
		logger = logrus.New()
	}
	
	return &AutoScaler{
		policies:           make(map[string]*ScalingPolicy),
		targets:            make(map[string]ScalingTarget),
		metrics:            make(map[string][]ScalingMetric),
		events:             make([]ScalingEvent, 0, config.MaxEvents),
		lastDecisions:      make(map[string]time.Time),
		logger:             logger,
		metricsWindow:      config.MetricsWindow,
		evaluationInterval: config.EvaluationInterval,
		maxEvents:          config.MaxEvents,
	}
}

// Start begins the autoscaling process
func (as *AutoScaler) Start(ctx context.Context) error {
	as.mutex.Lock()
	if as.running {
		as.mutex.Unlock()
		return fmt.Errorf("autoscaler is already running")
	}
	
	as.ctx, as.cancel = context.WithCancel(ctx)
	as.running = true
	as.mutex.Unlock()
	
	// Start evaluation loop
	go as.evaluationLoop()
	
	as.logger.Info("AutoScaler started")
	return nil
}

// Stop stops the autoscaling process
func (as *AutoScaler) Stop() {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	
	if !as.running {
		return
	}
	
	as.cancel()
	as.running = false
	
	as.logger.Info("AutoScaler stopped")
}

// RegisterPolicy registers a scaling policy
func (as *AutoScaler) RegisterPolicy(policy *ScalingPolicy) {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	
	as.policies[policy.Name] = policy
	as.lastDecisions[policy.Name] = time.Time{} // Initialize cooldown tracking
	
	as.logger.WithFields(logrus.Fields{
		"policy":     policy.Name,
		"metric":     policy.MetricName,
		"target":     policy.TargetValue,
		"min_instances": policy.MinInstances,
		"max_instances": policy.MaxInstances,
	}).Info("Registered scaling policy")
}

// RegisterTarget registers a scaling target
func (as *AutoScaler) RegisterTarget(target ScalingTarget) {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	
	as.targets[target.Name()] = target
	
	as.logger.WithFields(logrus.Fields{
		"target":   target.Name(),
		"replicas": target.CurrentReplicas(),
		"healthy":  target.IsHealthy(),
	}).Info("Registered scaling target")
}

// RecordMetric records a scaling metric
func (as *AutoScaler) RecordMetric(metric ScalingMetric) {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	
	if as.metrics[metric.Name] == nil {
		as.metrics[metric.Name] = make([]ScalingMetric, 0)
	}
	
	as.metrics[metric.Name] = append(as.metrics[metric.Name], metric)
	
	// Keep only recent metrics within the window
	cutoff := time.Now().Add(-as.metricsWindow)
	var filtered []ScalingMetric
	for _, m := range as.metrics[metric.Name] {
		if m.Timestamp.After(cutoff) {
			filtered = append(filtered, m)
		}
	}
	as.metrics[metric.Name] = filtered
}

// EvaluateScaling evaluates all policies and returns scaling decisions
func (as *AutoScaler) EvaluateScaling() []ScalingDecision {
	as.mutex.RLock()
	defer as.mutex.RUnlock()
	
	var decisions []ScalingDecision
	
	for _, policy := range as.policies {
		if !policy.Enabled {
			continue
		}
		
		// Check cooldown
		if time.Since(as.lastDecisions[policy.Name]) < policy.Cooldown {
			continue
		}
		
		decision := as.evaluatePolicy(policy)
		if decision.Direction != ScaleNone {
			decisions = append(decisions, decision)
		}
	}
	
	// Sort decisions by confidence (highest first)
	sort.Slice(decisions, func(i, j int) bool {
		return decisions[i].Confidence > decisions[j].Confidence
	})
	
	return decisions
}

// ApplyScalingDecision applies a scaling decision
func (as *AutoScaler) ApplyScalingDecision(decision ScalingDecision) error {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	
	// Find the target
	target, exists := as.targets[decision.PolicyName] // Assuming policy name matches target name
	if !exists {
		return fmt.Errorf("scaling target for policy %s not found", decision.PolicyName)
	}
	
	// Check if target is healthy
	if !target.IsHealthy() {
		return fmt.Errorf("scaling target %s is not healthy", target.Name())
	}
	
	// Create scaling event
	event := ScalingEvent{
		ID:           fmt.Sprintf("scale-%d", time.Now().UnixNano()),
		PolicyName:   decision.PolicyName,
		Direction:    decision.Direction,
		FromReplicas: decision.CurrentReplicas,
		ToReplicas:   decision.DesiredReplicas,
		Reason:       decision.Reason,
		StartTime:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}
	
	// Apply the scaling
	err := target.Scale(as.ctx, decision.DesiredReplicas)
	event.EndTime = time.Now()
	event.Duration = event.EndTime.Sub(event.StartTime)
	
	if err != nil {
		event.Success = false
		event.Error = err.Error()
		as.failedScales++
		
		as.logger.WithError(err).WithFields(logrus.Fields{
			"policy":          decision.PolicyName,
			"direction":       decision.Direction,
			"from_replicas":   decision.CurrentReplicas,
			"to_replicas":     decision.DesiredReplicas,
		}).Error("Failed to apply scaling decision")
	} else {
		event.Success = true
		as.successfulScales++
		
		// Update cooldown
		as.lastDecisions[decision.PolicyName] = time.Now()
		
		as.logger.WithFields(logrus.Fields{
			"policy":          decision.PolicyName,
			"direction":       decision.Direction,
			"from_replicas":   decision.CurrentReplicas,
			"to_replicas":     decision.DesiredReplicas,
			"reason":          decision.Reason,
			"confidence":      decision.Confidence,
		}).Info("Applied scaling decision")
	}
	
	// Record the event
	as.addEvent(event)
	as.totalScalingEvents++
	
	return err
}

// GetScalingEvents returns recent scaling events
func (as *AutoScaler) GetScalingEvents(limit int) []ScalingEvent {
	as.mutex.RLock()
	defer as.mutex.RUnlock()
	
	if limit <= 0 || limit > len(as.events) {
		limit = len(as.events)
	}
	
	result := make([]ScalingEvent, limit)
	copy(result, as.events[:limit])
	return result
}

// GetScalingStats returns scaling statistics
func (as *AutoScaler) GetScalingStats() map[string]interface{} {
	as.mutex.RLock()
	defer as.mutex.RUnlock()
	
	successRate := float64(0)
	if as.totalScalingEvents > 0 {
		successRate = float64(as.successfulScales) / float64(as.totalScalingEvents) * 100
	}
	
	return map[string]interface{}{
		"total_scaling_events": as.totalScalingEvents,
		"successful_scales":    as.successfulScales,
		"failed_scales":       as.failedScales,
		"success_rate":        successRate,
		"active_policies":     len(as.policies),
		"registered_targets":  len(as.targets),
		"recent_events":       len(as.events),
	}
}

// GetCurrentStatus returns current autoscaler status
func (as *AutoScaler) GetCurrentStatus() map[string]interface{} {
	as.mutex.RLock()
	defer as.mutex.RUnlock()
	
	status := map[string]interface{}{
		"running":          as.running,
		"policies":         make(map[string]interface{}),
		"targets":          make(map[string]interface{}),
		"last_evaluation":  time.Now(), // This would be tracked in real implementation
	}
	
	for name, policy := range as.policies {
		status["policies"].(map[string]interface{})[name] = map[string]interface{}{
			"enabled":      policy.Enabled,
			"metric":       policy.MetricName,
			"target_value": policy.TargetValue,
			"min_instances": policy.MinInstances,
			"max_instances": policy.MaxInstances,
			"last_decision": as.lastDecisions[name],
		}
	}
	
	for name, target := range as.targets {
		status["targets"].(map[string]interface{})[name] = map[string]interface{}{
			"current_replicas": target.CurrentReplicas(),
			"healthy":         target.IsHealthy(),
		}
	}
	
	return status
}

// Internal methods
func (as *AutoScaler) evaluationLoop() {
	ticker := time.NewTicker(as.evaluationInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-as.ctx.Done():
			return
		case <-ticker.C:
			decisions := as.EvaluateScaling()
			
			// Apply decisions with high confidence
			for _, decision := range decisions {
				if decision.Confidence >= 0.8 {
					if err := as.ApplyScalingDecision(decision); err != nil {
						as.logger.WithError(err).
							WithField("policy", decision.PolicyName).
							Warn("Failed to apply automatic scaling decision")
					}
				}
			}
		}
	}
}

func (as *AutoScaler) evaluatePolicy(policy *ScalingPolicy) ScalingDecision {
	// Get recent metrics for this policy
	metrics := as.getRecentMetrics(policy.MetricName, policy.EvaluationPeriod)
	
	decision := ScalingDecision{
		PolicyName:  policy.Name,
		Direction:   ScaleNone,
		Timestamp:   time.Now(),
		TargetValue: policy.TargetValue,
		Metadata:    make(map[string]interface{}),
	}
	
	// Check if we have enough data points
	if len(metrics) < policy.DataPointsRequired {
		decision.Reason = fmt.Sprintf("Insufficient data points: %d < %d", len(metrics), policy.DataPointsRequired)
		decision.Confidence = 0.0
		return decision
	}
	
	// Calculate average metric value
	avgValue := as.calculateAverageMetric(metrics)
	decision.MetricValue = avgValue
	
	// Get current replicas from target
	target, exists := as.targets[policy.Name]
	if !exists {
		decision.Reason = "Target not found"
		decision.Confidence = 0.0
		return decision
	}
	
	currentReplicas := target.CurrentReplicas()
	decision.CurrentReplicas = currentReplicas
	
	// Determine scaling direction
	if avgValue > policy.ScaleUpThreshold {
		// Scale up
		newReplicas := as.calculateNewReplicas(currentReplicas, policy.ScaleUpStep, policy.MaxInstances, true)
		if newReplicas > currentReplicas {
			decision.Direction = ScaleUp
			decision.DesiredReplicas = newReplicas
			decision.Reason = fmt.Sprintf("Metric %.2f > threshold %.2f", avgValue, policy.ScaleUpThreshold)
			decision.Confidence = as.calculateConfidence(avgValue, policy.ScaleUpThreshold, metrics)
		}
	} else if avgValue < policy.ScaleDownThreshold {
		// Scale down
		newReplicas := as.calculateNewReplicas(currentReplicas, policy.ScaleDownStep, policy.MinInstances, false)
		if newReplicas < currentReplicas {
			decision.Direction = ScaleDown
			decision.DesiredReplicas = newReplicas
			decision.Reason = fmt.Sprintf("Metric %.2f < threshold %.2f", avgValue, policy.ScaleDownThreshold)
			decision.Confidence = as.calculateConfidence(policy.ScaleDownThreshold, avgValue, metrics)
		}
	}
	
	// Apply constraints
	if decision.Direction != ScaleNone {
		decision = as.applyConstraints(decision, policy)
	}
	
	return decision
}

func (as *AutoScaler) getRecentMetrics(metricName string, period time.Duration) []ScalingMetric {
	metrics := as.metrics[metricName]
	if metrics == nil {
		return []ScalingMetric{}
	}
	
	cutoff := time.Now().Add(-period)
	var recent []ScalingMetric
	for _, metric := range metrics {
		if metric.Timestamp.After(cutoff) {
			recent = append(recent, metric)
		}
	}
	
	return recent
}

func (as *AutoScaler) calculateAverageMetric(metrics []ScalingMetric) float64 {
	if len(metrics) == 0 {
		return 0.0
	}
	
	sum := 0.0
	for _, metric := range metrics {
		sum += metric.Value
	}
	
	return sum / float64(len(metrics))
}

func (as *AutoScaler) calculateNewReplicas(current, step, limit int, scaleUp bool) int {
	var newReplicas int
	
	if scaleUp {
		newReplicas = current + step
		if newReplicas > limit {
			newReplicas = limit
		}
	} else {
		newReplicas = current - step
		if newReplicas < limit {
			newReplicas = limit
		}
	}
	
	return newReplicas
}

func (as *AutoScaler) calculateConfidence(value1, value2 float64, metrics []ScalingMetric) float64 {
	// Calculate confidence based on:
	// 1. How far the metric is from the threshold
	// 2. Consistency of recent metrics
	// 3. Number of data points
	
	distance := math.Abs(value1 - value2)
	maxDistance := math.Max(value1, value2)
	
	distanceScore := 0.0
	if maxDistance > 0 {
		distanceScore = distance / maxDistance
	}
	
	// Calculate consistency (lower standard deviation = higher confidence)
	consistency := as.calculateConsistency(metrics)
	
	// Data points score (more data = higher confidence)
	dataPointsScore := math.Min(float64(len(metrics))/10.0, 1.0)
	
	// Combine scores
	confidence := (distanceScore + consistency + dataPointsScore) / 3.0
	
	// Ensure confidence is between 0 and 1
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}
	
	return confidence
}

func (as *AutoScaler) calculateConsistency(metrics []ScalingMetric) float64 {
	if len(metrics) < 2 {
		return 0.5 // Neutral consistency for insufficient data
	}
	
	// Calculate standard deviation
	mean := as.calculateAverageMetric(metrics)
	variance := 0.0
	
	for _, metric := range metrics {
		diff := metric.Value - mean
		variance += diff * diff
	}
	
	variance /= float64(len(metrics))
	stddev := math.Sqrt(variance)
	
	// Convert to consistency score (lower stddev = higher consistency)
	// Normalize by mean to get coefficient of variation
	cv := 0.0
	if mean > 0 {
		cv = stddev / mean
	}
	
	// Convert CV to consistency score (inverse relationship)
	consistency := 1.0 / (1.0 + cv)
	
	return consistency
}

func (as *AutoScaler) applyConstraints(decision ScalingDecision, policy *ScalingPolicy) ScalingDecision {
	// Apply any additional constraints defined in the policy
	for constraint, value := range policy.Constraints {
		switch constraint {
		case "max_scale_factor":
			// Limit how much we can scale at once
			scaleFactor := float64(decision.DesiredReplicas) / float64(decision.CurrentReplicas)
			if scaleFactor > value {
				decision.DesiredReplicas = int(float64(decision.CurrentReplicas) * value)
				decision.Reason += fmt.Sprintf(" (limited by max_scale_factor %.2f)", value)
			}
		case "min_confidence":
			// Require minimum confidence
			if decision.Confidence < value {
				decision.Direction = ScaleNone
				decision.Reason = fmt.Sprintf("Confidence %.2f below minimum %.2f", decision.Confidence, value)
			}
		}
	}
	
	return decision
}

func (as *AutoScaler) addEvent(event ScalingEvent) {
	// Add to beginning of slice (most recent first)
	as.events = append([]ScalingEvent{event}, as.events...)
	
	// Trim to max size
	if len(as.events) > as.maxEvents {
		as.events = as.events[:as.maxEvents]
	}
}

// Simple implementation of ScalingTarget for testing
type SimpleScalingTarget struct {
	name     string
	replicas int
	healthy  bool
	mutex    sync.RWMutex
}

// NewSimpleScalingTarget creates a simple scaling target for testing
func NewSimpleScalingTarget(name string, initialReplicas int) *SimpleScalingTarget {
	return &SimpleScalingTarget{
		name:     name,
		replicas: initialReplicas,
		healthy:  true,
	}
}

func (sst *SimpleScalingTarget) Name() string {
	return sst.name
}

func (sst *SimpleScalingTarget) CurrentReplicas() int {
	sst.mutex.RLock()
	defer sst.mutex.RUnlock()
	return sst.replicas
}

func (sst *SimpleScalingTarget) Scale(ctx context.Context, replicas int) error {
	sst.mutex.Lock()
	defer sst.mutex.Unlock()
	
	if replicas < 0 {
		return fmt.Errorf("replicas cannot be negative")
	}
	
	sst.replicas = replicas
	return nil
}

func (sst *SimpleScalingTarget) IsHealthy() bool {
	sst.mutex.RLock()
	defer sst.mutex.RUnlock()
	return sst.healthy
}

func (sst *SimpleScalingTarget) SetHealthy(healthy bool) {
	sst.mutex.Lock()
	defer sst.mutex.Unlock()
	sst.healthy = healthy
}