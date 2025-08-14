package autoscaling

import (
	"context"
	"fmt"
	"time"
)

// CPUTrigger scales based on CPU utilization
type CPUTrigger struct {
	config TriggerConfig
}

// NewCPUTrigger creates a new CPU-based scaling trigger
func NewCPUTrigger(targetUtilization float64) *CPUTrigger {
	return &CPUTrigger{
		config: TriggerConfig{
			MetricName:       "cpu_utilization_percent",
			Threshold:        targetUtilization,
			Comparison:       GreaterThan,
			EvaluationWindow: 5 * time.Minute,
			MinDataPoints:    3,
		},
	}
}

// Name returns the trigger name
func (ct *CPUTrigger) Name() string {
	return "cpu_utilization"
}

// Config returns the trigger configuration
func (ct *CPUTrigger) Config() TriggerConfig {
	return ct.config
}

// Evaluate evaluates CPU utilization and makes scaling decisions
func (ct *CPUTrigger) Evaluate(ctx context.Context, metrics map[string]interface{}) (ScalingDecision, error) {
	decision := ScalingDecision{
		Direction: ScaleNone,
		Timestamp: time.Now(),
		Metrics:   make(map[string]interface{}),
	}
	
	// Get CPU utilization from metrics
	cpuValue, exists := metrics[ct.config.MetricName]
	if !exists {
		return decision, fmt.Errorf("metric %s not found", ct.config.MetricName)
	}
	
	cpuUtilization, ok := cpuValue.(float64)
	if !ok {
		// Try to convert from int
		if intValue, ok := cpuValue.(int); ok {
			cpuUtilization = float64(intValue)
		} else {
			return decision, fmt.Errorf("metric %s is not a number", ct.config.MetricName)
		}
	}
	
	decision.Metrics["cpu_utilization"] = cpuUtilization
	decision.Metrics["threshold"] = ct.config.Threshold
	
	// Determine scaling direction and urgency
	if cpuUtilization > ct.config.Threshold {
		// Scale up
		decision.Direction = ScaleUp
		decision.Reason = fmt.Sprintf("CPU utilization (%.1f%%) exceeds threshold (%.1f%%)", 
			cpuUtilization, ct.config.Threshold)
		
		// Determine urgency based on how far above threshold
		overagePercent := (cpuUtilization - ct.config.Threshold) / ct.config.Threshold * 100
		switch {
		case overagePercent > 50: // 50% over threshold
			decision.Urgency = UrgencyCritical
		case overagePercent > 25: // 25% over threshold
			decision.Urgency = UrgencyHigh
		case overagePercent > 10: // 10% over threshold
			decision.Urgency = UrgencyMedium
		default:
			decision.Urgency = UrgencyLow
		}
		
	} else if cpuUtilization < (ct.config.Threshold * 0.5) {
		// Scale down if CPU is less than 50% of threshold
		decision.Direction = ScaleDown
		decision.Reason = fmt.Sprintf("CPU utilization (%.1f%%) is well below threshold (%.1f%%)", 
			cpuUtilization, ct.config.Threshold)
		
		// Scale down is generally less urgent
		if cpuUtilization < (ct.config.Threshold * 0.3) {
			decision.Urgency = UrgencyMedium
		} else {
			decision.Urgency = UrgencyLow
		}
	}
	
	return decision, nil
}

// ResponseTimeTrigger scales based on response time
type ResponseTimeTrigger struct {
	config TriggerConfig
}

// NewResponseTimeTrigger creates a new response time-based scaling trigger
func NewResponseTimeTrigger(targetResponseTimeMs float64) *ResponseTimeTrigger {
	return &ResponseTimeTrigger{
		config: TriggerConfig{
			MetricName:       "avg_response_time_ms",
			Threshold:        targetResponseTimeMs,
			Comparison:       GreaterThan,
			EvaluationWindow: 3 * time.Minute,
			MinDataPoints:    5,
		},
	}
}

// Name returns the trigger name
func (rt *ResponseTimeTrigger) Name() string {
	return "response_time"
}

// Config returns the trigger configuration
func (rt *ResponseTimeTrigger) Config() TriggerConfig {
	return rt.config
}

// Evaluate evaluates response time and makes scaling decisions
func (rt *ResponseTimeTrigger) Evaluate(ctx context.Context, metrics map[string]interface{}) (ScalingDecision, error) {
	decision := ScalingDecision{
		Direction: ScaleNone,
		Timestamp: time.Now(),
		Metrics:   make(map[string]interface{}),
	}
	
	// Get response time from metrics
	responseTimeValue, exists := metrics[rt.config.MetricName]
	if !exists {
		return decision, fmt.Errorf("metric %s not found", rt.config.MetricName)
	}
	
	responseTime, ok := responseTimeValue.(float64)
	if !ok {
		if intValue, ok := responseTimeValue.(int); ok {
			responseTime = float64(intValue)
		} else {
			return decision, fmt.Errorf("metric %s is not a number", rt.config.MetricName)
		}
	}
	
	decision.Metrics["response_time_ms"] = responseTime
	decision.Metrics["threshold"] = rt.config.Threshold
	
	// Determine scaling direction and urgency
	if responseTime > rt.config.Threshold {
		// Scale up for high response times
		decision.Direction = ScaleUp
		decision.Reason = fmt.Sprintf("Response time (%.1fms) exceeds threshold (%.1fms)", 
			responseTime, rt.config.Threshold)
		
		// Determine urgency based on how far above threshold
		overageRatio := responseTime / rt.config.Threshold
		switch {
		case overageRatio > 3.0: // 3x threshold
			decision.Urgency = UrgencyCritical
		case overageRatio > 2.0: // 2x threshold
			decision.Urgency = UrgencyHigh
		case overageRatio > 1.5: // 1.5x threshold
			decision.Urgency = UrgencyMedium
		default:
			decision.Urgency = UrgencyLow
		}
		
	} else if responseTime < (rt.config.Threshold * 0.3) {
		// Scale down if response time is very low
		decision.Direction = ScaleDown
		decision.Reason = fmt.Sprintf("Response time (%.1fms) is well below threshold (%.1fms)", 
			responseTime, rt.config.Threshold)
		decision.Urgency = UrgencyLow
	}
	
	return decision, nil
}

// QueueLengthTrigger scales based on queue length
type QueueLengthTrigger struct {
	config TriggerConfig
}

// NewQueueLengthTrigger creates a new queue length-based scaling trigger
func NewQueueLengthTrigger(maxQueueLength float64) *QueueLengthTrigger {
	return &QueueLengthTrigger{
		config: TriggerConfig{
			MetricName:       "active_requests",
			Threshold:        maxQueueLength,
			Comparison:       GreaterThan,
			EvaluationWindow: 1 * time.Minute,
			MinDataPoints:    2,
		},
	}
}

// Name returns the trigger name
func (qt *QueueLengthTrigger) Name() string {
	return "queue_length"
}

// Config returns the trigger configuration
func (qt *QueueLengthTrigger) Config() TriggerConfig {
	return qt.config
}

// Evaluate evaluates queue length and makes scaling decisions
func (qt *QueueLengthTrigger) Evaluate(ctx context.Context, metrics map[string]interface{}) (ScalingDecision, error) {
	decision := ScalingDecision{
		Direction: ScaleNone,
		Timestamp: time.Now(),
		Metrics:   make(map[string]interface{}),
	}
	
	// Get queue length from metrics
	queueValue, exists := metrics[qt.config.MetricName]
	if !exists {
		return decision, fmt.Errorf("metric %s not found", qt.config.MetricName)
	}
	
	queueLength, ok := queueValue.(float64)
	if !ok {
		if intValue, ok := queueValue.(int64); ok {
			queueLength = float64(intValue)
		} else {
			return decision, fmt.Errorf("metric %s is not a number", qt.config.MetricName)
		}
	}
	
	decision.Metrics["queue_length"] = queueLength
	decision.Metrics["threshold"] = qt.config.Threshold
	
	// Determine scaling direction and urgency
	if queueLength > qt.config.Threshold {
		// Scale up for high queue length
		decision.Direction = ScaleUp
		decision.Reason = fmt.Sprintf("Queue length (%.0f) exceeds threshold (%.0f)", 
			queueLength, qt.config.Threshold)
		
		// Queue length is critical for user experience
		overageRatio := queueLength / qt.config.Threshold
		switch {
		case overageRatio > 5.0: // 5x threshold
			decision.Urgency = UrgencyCritical
		case overageRatio > 3.0: // 3x threshold
			decision.Urgency = UrgencyHigh
		case overageRatio > 2.0: // 2x threshold
			decision.Urgency = UrgencyMedium
		default:
			decision.Urgency = UrgencyLow
		}
		
	} else if queueLength == 0 {
		// Consider scaling down if queue is empty (but be conservative)
		decision.Direction = ScaleDown
		decision.Reason = "Queue is empty, consider scaling down"
		decision.Urgency = UrgencyLow
	}
	
	return decision, nil
}

// ErrorRateTrigger scales based on error rate
type ErrorRateTrigger struct {
	config TriggerConfig
}

// NewErrorRateTrigger creates a new error rate-based scaling trigger
func NewErrorRateTrigger(maxErrorRatePercent float64) *ErrorRateTrigger {
	return &ErrorRateTrigger{
		config: TriggerConfig{
			MetricName:       "error_rate_percent",
			Threshold:        maxErrorRatePercent,
			Comparison:       GreaterThan,
			EvaluationWindow: 2 * time.Minute,
			MinDataPoints:    3,
		},
	}
}

// Name returns the trigger name
func (et *ErrorRateTrigger) Name() string {
	return "error_rate"
}

// Config returns the trigger configuration
func (et *ErrorRateTrigger) Config() TriggerConfig {
	return et.config
}

// Evaluate evaluates error rate and makes scaling decisions
func (et *ErrorRateTrigger) Evaluate(ctx context.Context, metrics map[string]interface{}) (ScalingDecision, error) {
	decision := ScalingDecision{
		Direction: ScaleNone,
		Timestamp: time.Now(),
		Metrics:   make(map[string]interface{}),
	}
	
	// Get error rate from metrics
	errorRateValue, exists := metrics[et.config.MetricName]
	if !exists {
		return decision, fmt.Errorf("metric %s not found", et.config.MetricName)
	}
	
	errorRate, ok := errorRateValue.(float64)
	if !ok {
		if intValue, ok := errorRateValue.(int); ok {
			errorRate = float64(intValue)
		} else {
			return decision, fmt.Errorf("metric %s is not a number", et.config.MetricName)
		}
	}
	
	decision.Metrics["error_rate_percent"] = errorRate
	decision.Metrics["threshold"] = et.config.Threshold
	
	// Only scale up for high error rates (scaling down on low error rates is risky)
	if errorRate > et.config.Threshold {
		decision.Direction = ScaleUp
		decision.Reason = fmt.Sprintf("Error rate (%.2f%%) exceeds threshold (%.2f%%)", 
			errorRate, et.config.Threshold)
		
		// High error rates are critical
		switch {
		case errorRate > 10.0:
			decision.Urgency = UrgencyCritical
		case errorRate > 5.0:
			decision.Urgency = UrgencyHigh
		case errorRate > 2.0:
			decision.Urgency = UrgencyMedium
		default:
			decision.Urgency = UrgencyLow
		}
	}
	
	return decision, nil
}