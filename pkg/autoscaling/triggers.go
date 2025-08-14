package autoscaling

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AutoScaler manages automatic scaling based on metrics and triggers
type AutoScaler struct {
	triggers []ScalingTrigger
	policies []ScalingPolicy
	executor ScalingExecutor
	
	mu       sync.RWMutex
	state    AutoScalerState
	metrics  AutoScalerMetrics
}

// ScalingTrigger defines conditions that trigger scaling actions
type ScalingTrigger interface {
	Name() string
	Evaluate(ctx context.Context, metrics map[string]interface{}) (ScalingDecision, error)
	Config() TriggerConfig
}

// ScalingPolicy defines how scaling should be performed
type ScalingPolicy interface {
	Name() string
	CanScale(current, target int, direction ScalingDirection) bool
	CalculateTarget(current int, metrics map[string]interface{}, decision ScalingDecision) int
	Config() PolicyConfig
}

// ScalingExecutor performs the actual scaling operations
type ScalingExecutor interface {
	ScaleUp(ctx context.Context, target int) error
	ScaleDown(ctx context.Context, target int) error
	GetCurrentScale() (int, error)
}

// ScalingDecision represents a scaling decision
type ScalingDecision struct {
	Direction ScalingDirection
	Urgency   ScalingUrgency
	Reason    string
	Metrics   map[string]interface{}
	Timestamp time.Time
}

// ScalingDirection indicates the direction of scaling
type ScalingDirection string

const (
	ScaleUp   ScalingDirection = "up"
	ScaleDown ScalingDirection = "down"
	ScaleNone ScalingDirection = "none"
)

// ScalingUrgency indicates how urgent the scaling action is
type ScalingUrgency string

const (
	UrgencyLow    ScalingUrgency = "low"
	UrgencyMedium ScalingUrgency = "medium"
	UrgencyHigh   ScalingUrgency = "high"
	UrgencyCritical ScalingUrgency = "critical"
)

// AutoScalerState tracks the current state of the autoscaler
type AutoScalerState struct {
	Enabled           bool
	CurrentReplicas   int
	TargetReplicas    int
	LastScalingAction time.Time
	LastDecision      ScalingDecision
	CooldownUntil     time.Time
}

// AutoScalerMetrics tracks autoscaler performance metrics
type AutoScalerMetrics struct {
	TotalEvaluations     int64
	ScaleUpActions       int64
	ScaleDownActions     int64
	FailedActions        int64
	AverageResponseTime  time.Duration
	LastEvaluation       time.Time
}

// TriggerConfig configures a scaling trigger
type TriggerConfig struct {
	MetricName     string
	Threshold      float64
	Comparison     ComparisonOperator
	EvaluationWindow time.Duration
	MinDataPoints  int
}

// PolicyConfig configures a scaling policy
type PolicyConfig struct {
	CooldownPeriod  time.Duration
	MinReplicas     int
	MaxReplicas     int
	ScaleUpFactor   float64
	ScaleDownFactor float64
}

// ComparisonOperator defines how to compare metrics to thresholds
type ComparisonOperator string

const (
	GreaterThan    ComparisonOperator = ">"
	GreaterOrEqual ComparisonOperator = ">="
	LessThan       ComparisonOperator = "<"
	LessOrEqual    ComparisonOperator = "<="
	Equal          ComparisonOperator = "=="
	NotEqual       ComparisonOperator = "!="
)

// NewAutoScaler creates a new autoscaler instance
func NewAutoScaler(executor ScalingExecutor) *AutoScaler {
	return &AutoScaler{
		executor: executor,
		state: AutoScalerState{
			Enabled: true,
		},
		metrics: AutoScalerMetrics{
			LastEvaluation: time.Now(),
		},
	}
}

// AddTrigger adds a scaling trigger
func (as *AutoScaler) AddTrigger(trigger ScalingTrigger) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.triggers = append(as.triggers, trigger)
}

// AddPolicy adds a scaling policy
func (as *AutoScaler) AddPolicy(policy ScalingPolicy) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.policies = append(as.policies, policy)
}

// Evaluate evaluates all triggers and makes scaling decisions
func (as *AutoScaler) Evaluate(ctx context.Context, metrics map[string]interface{}) error {
	start := time.Now()
	defer func() {
		as.mu.Lock()
		as.metrics.TotalEvaluations++
		as.metrics.AverageResponseTime = (as.metrics.AverageResponseTime + time.Since(start)) / 2
		as.metrics.LastEvaluation = time.Now()
		as.mu.Unlock()
	}()
	
	as.mu.RLock()
	if !as.state.Enabled {
		as.mu.RUnlock()
		return nil
	}
	
	// Check if we're in cooldown period
	if time.Now().Before(as.state.CooldownUntil) {
		as.mu.RUnlock()
		return nil
	}
	as.mu.RUnlock()
	
	// Evaluate all triggers
	var decisions []ScalingDecision
	for _, trigger := range as.triggers {
		decision, err := trigger.Evaluate(ctx, metrics)
		if err != nil {
			continue // Log error but continue with other triggers
		}
		
		if decision.Direction != ScaleNone {
			decisions = append(decisions, decision)
		}
	}
	
	// No scaling decisions
	if len(decisions) == 0 {
		return nil
	}
	
	// Choose the most urgent decision
	finalDecision := as.chooseBestDecision(decisions)
	
	// Apply policies to validate and adjust the decision
	targetReplicas, err := as.applyPolicies(finalDecision, metrics)
	if err != nil {
		return fmt.Errorf("failed to apply policies: %w", err)
	}
	
	// Execute scaling if needed
	currentReplicas, err := as.executor.GetCurrentScale()
	if err != nil {
		return fmt.Errorf("failed to get current scale: %w", err)
	}
	
	if currentReplicas == targetReplicas {
		return nil // No scaling needed
	}
	
	// Perform scaling
	err = as.executeScaling(ctx, currentReplicas, targetReplicas, finalDecision.Direction)
	if err != nil {
		as.mu.Lock()
		as.metrics.FailedActions++
		as.mu.Unlock()
		return fmt.Errorf("failed to execute scaling: %w", err)
	}
	
	// Update state
	as.mu.Lock()
	as.state.CurrentReplicas = currentReplicas
	as.state.TargetReplicas = targetReplicas
	as.state.LastScalingAction = time.Now()
	as.state.LastDecision = finalDecision
	
	// Set cooldown period based on urgency
	cooldownDuration := as.calculateCooldown(finalDecision.Urgency)
	as.state.CooldownUntil = time.Now().Add(cooldownDuration)
	
	// Update metrics
	if finalDecision.Direction == ScaleUp {
		as.metrics.ScaleUpActions++
	} else {
		as.metrics.ScaleDownActions++
	}
	as.mu.Unlock()
	
	return nil
}

// chooseBestDecision selects the most appropriate scaling decision from multiple options
func (as *AutoScaler) chooseBestDecision(decisions []ScalingDecision) ScalingDecision {
	if len(decisions) == 0 {
		return ScalingDecision{Direction: ScaleNone}
	}
	
	if len(decisions) == 1 {
		return decisions[0]
	}
	
	// Priority: Critical > High > Medium > Low
	// Direction priority: ScaleUp > ScaleDown (safety first)
	best := decisions[0]
	
	for _, decision := range decisions[1:] {
		if as.isMoreUrgent(decision.Urgency, best.Urgency) {
			best = decision
		} else if decision.Urgency == best.Urgency {
			// Same urgency, prefer scale up for safety
			if decision.Direction == ScaleUp && best.Direction == ScaleDown {
				best = decision
			}
		}
	}
	
	return best
}

// isMoreUrgent returns true if urgency1 is more urgent than urgency2
func (as *AutoScaler) isMoreUrgent(urgency1, urgency2 ScalingUrgency) bool {
	urgencyOrder := map[ScalingUrgency]int{
		UrgencyLow:      1,
		UrgencyMedium:   2,
		UrgencyHigh:     3,
		UrgencyCritical: 4,
	}
	
	return urgencyOrder[urgency1] > urgencyOrder[urgency2]
}

// applyPolicies applies scaling policies to validate and adjust the target replicas
func (as *AutoScaler) applyPolicies(decision ScalingDecision, metrics map[string]interface{}) (int, error) {
	currentReplicas, err := as.executor.GetCurrentScale()
	if err != nil {
		return 0, fmt.Errorf("failed to get current scale: %w", err)
	}
	
	targetReplicas := currentReplicas
	
	// Apply each policy
	for _, policy := range as.policies {
		newTarget := policy.CalculateTarget(currentReplicas, metrics, decision)
		
		if policy.CanScale(currentReplicas, newTarget, decision.Direction) {
			targetReplicas = newTarget
		}
		
		// Enforce min/max constraints
		config := policy.Config()
		if targetReplicas < config.MinReplicas {
			targetReplicas = config.MinReplicas
		}
		if targetReplicas > config.MaxReplicas {
			targetReplicas = config.MaxReplicas
		}
	}
	
	return targetReplicas, nil
}

// executeScaling performs the actual scaling operation
func (as *AutoScaler) executeScaling(ctx context.Context, current, target int, direction ScalingDirection) error {
	switch direction {
	case ScaleUp:
		return as.executor.ScaleUp(ctx, target)
	case ScaleDown:
		return as.executor.ScaleDown(ctx, target)
	default:
		return nil
	}
}

// calculateCooldown calculates the cooldown period based on urgency
func (as *AutoScaler) calculateCooldown(urgency ScalingUrgency) time.Duration {
	switch urgency {
	case UrgencyCritical:
		return 30 * time.Second
	case UrgencyHigh:
		return 2 * time.Minute
	case UrgencyMedium:
		return 5 * time.Minute
	case UrgencyLow:
		return 10 * time.Minute
	default:
		return 5 * time.Minute
	}
}

// GetState returns the current autoscaler state
func (as *AutoScaler) GetState() AutoScalerState {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.state
}

// GetMetrics returns autoscaler metrics
func (as *AutoScaler) GetMetrics() AutoScalerMetrics {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.metrics
}

// Enable enables the autoscaler
func (as *AutoScaler) Enable() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.state.Enabled = true
}

// Disable disables the autoscaler
func (as *AutoScaler) Disable() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.state.Enabled = false
}

// IsEnabled returns true if the autoscaler is enabled
func (as *AutoScaler) IsEnabled() bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.state.Enabled
}

// StartMonitoring starts the autoscaler monitoring loop
func (as *AutoScaler) StartMonitoring(ctx context.Context, interval time.Duration, metricsProvider func(ctx context.Context) (map[string]interface{}, error)) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			metrics, err := metricsProvider(ctx)
			if err != nil {
				continue // Log error but continue monitoring
			}
			
			if err := as.Evaluate(ctx, metrics); err != nil {
				// Log error but continue monitoring
				continue
			}
		}
	}
}