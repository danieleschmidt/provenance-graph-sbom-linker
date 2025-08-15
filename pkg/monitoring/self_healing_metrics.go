package monitoring

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"github.com/sirupsen/logrus"
)

// SelfHealingMetrics tracks metrics for self-healing pipeline operations
type SelfHealingMetrics struct {
	meter                    metric.Meter
	healingActionsCounter    metric.Int64Counter
	componentHealthGauge     metric.Float64Gauge
	recoveryTimeHistogram    metric.Float64Histogram
	scalingEventsCounter     metric.Int64Counter
	circuitBreakerStateGauge metric.Int64Gauge
	resourceUsageGauge       metric.Float64Gauge
	mutex                    sync.RWMutex
	logger                   *logrus.Logger
}

// NewSelfHealingMetrics creates a new self-healing metrics collector
func NewSelfHealingMetrics(logger *logrus.Logger) (*SelfHealingMetrics, error) {
	meter := otel.Meter("provenance-linker/self-healing")
	
	healingActionsCounter, err := meter.Int64Counter(
		"self_healing_actions_total",
		metric.WithDescription("Total number of self-healing actions taken"),
	)
	if err != nil {
		return nil, err
	}
	
	componentHealthGauge, err := meter.Float64Gauge(
		"component_health_status",
		metric.WithDescription("Health status of pipeline components (0=healthy, 1=degraded, 2=unhealthy, 3=critical)"),
	)
	if err != nil {
		return nil, err
	}
	
	recoveryTimeHistogram, err := meter.Float64Histogram(
		"component_recovery_time_seconds",
		metric.WithDescription("Time taken for components to recover from failures"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}
	
	scalingEventsCounter, err := meter.Int64Counter(
		"scaling_events_total",
		metric.WithDescription("Total number of scaling events (up/down)"),
	)
	if err != nil {
		return nil, err
	}
	
	circuitBreakerStateGauge, err := meter.Int64Gauge(
		"circuit_breaker_state",
		metric.WithDescription("Circuit breaker state (0=closed, 1=half-open, 2=open)"),
	)
	if err != nil {
		return nil, err
	}
	
	resourceUsageGauge, err := meter.Float64Gauge(
		"resource_usage_percent",
		metric.WithDescription("Resource usage percentage for components"),
	)
	if err != nil {
		return nil, err
	}
	
	return &SelfHealingMetrics{
		meter:                    meter,
		healingActionsCounter:    healingActionsCounter,
		componentHealthGauge:     componentHealthGauge,
		recoveryTimeHistogram:    recoveryTimeHistogram,
		scalingEventsCounter:     scalingEventsCounter,
		circuitBreakerStateGauge: circuitBreakerStateGauge,
		resourceUsageGauge:       resourceUsageGauge,
		logger:                   logger,
	}, nil
}

// RecordHealingAction records a self-healing action
func (shm *SelfHealingMetrics) RecordHealingAction(ctx context.Context, actionType, componentID, reason string, success bool) {
	attributes := []attribute.KeyValue{
		attribute.String("action_type", actionType),
		attribute.String("component_id", componentID),
		attribute.String("reason", reason),
		attribute.Bool("success", success),
	}
	
	shm.healingActionsCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
	
	shm.logger.WithFields(logrus.Fields{
		"action_type": actionType,
		"component_id": componentID,
		"reason": reason,
		"success": success,
	}).Info("Recorded healing action")
}

// UpdateComponentHealth updates component health metrics
func (shm *SelfHealingMetrics) UpdateComponentHealth(ctx context.Context, componentID string, healthStatus int, errorRate, latency float64) {
	attributes := []attribute.KeyValue{
		attribute.String("component_id", componentID),
	}
	
	shm.componentHealthGauge.Record(ctx, float64(healthStatus), metric.WithAttributes(attributes...))
	
	// Record additional health metrics
	errorRateAttrs := append(attributes, attribute.String("metric_type", "error_rate"))
	shm.resourceUsageGauge.Record(ctx, errorRate, metric.WithAttributes(errorRateAttrs...))
	
	latencyAttrs := append(attributes, attribute.String("metric_type", "latency_ms"))
	shm.resourceUsageGauge.Record(ctx, latency, metric.WithAttributes(latencyAttrs...))
}

// RecordRecoveryTime records the time taken for a component to recover
func (shm *SelfHealingMetrics) RecordRecoveryTime(ctx context.Context, componentID string, recoveryTime time.Duration) {
	attributes := []attribute.KeyValue{
		attribute.String("component_id", componentID),
	}
	
	shm.recoveryTimeHistogram.Record(ctx, recoveryTime.Seconds(), metric.WithAttributes(attributes...))
	
	shm.logger.WithFields(logrus.Fields{
		"component_id": componentID,
		"recovery_time_ms": recoveryTime.Milliseconds(),
	}).Info("Component recovered")
}

// RecordScalingEvent records a scaling event (up or down)
func (shm *SelfHealingMetrics) RecordScalingEvent(ctx context.Context, direction, reason string, oldWorkers, newWorkers int) {
	attributes := []attribute.KeyValue{
		attribute.String("direction", direction),
		attribute.String("reason", reason),
		attribute.Int("old_workers", oldWorkers),
		attribute.Int("new_workers", newWorkers),
	}
	
	shm.scalingEventsCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
	
	shm.logger.WithFields(logrus.Fields{
		"direction": direction,
		"reason": reason,
		"old_workers": oldWorkers,
		"new_workers": newWorkers,
	}).Info("Scaling event occurred")
}

// UpdateCircuitBreakerState updates circuit breaker state metrics
func (shm *SelfHealingMetrics) UpdateCircuitBreakerState(ctx context.Context, componentID string, state int) {
	attributes := []attribute.KeyValue{
		attribute.String("component_id", componentID),
	}
	
	shm.circuitBreakerStateGauge.Record(ctx, int64(state), metric.WithAttributes(attributes...))
}

// UpdateResourceUsage updates resource usage metrics
func (shm *SelfHealingMetrics) UpdateResourceUsage(ctx context.Context, componentID, resourceType string, usage float64) {
	attributes := []attribute.KeyValue{
		attribute.String("component_id", componentID),
		attribute.String("resource_type", resourceType),
	}
	
	shm.resourceUsageGauge.Record(ctx, usage, metric.WithAttributes(attributes...))
}

// PipelineHealthMetrics provides comprehensive health metrics for the entire pipeline
type PipelineHealthMetrics struct {
	OverallHealth         string                 `json:"overall_health"`
	ComponentHealthScores map[string]float64     `json:"component_health_scores"`
	ActiveHealingActions  int                    `json:"active_healing_actions"`
	TotalHealingActions   int64                  `json:"total_healing_actions"`
	CircuitBreakerStates  map[string]string      `json:"circuit_breaker_states"`
	ResourceUtilization   ResourceUtilization    `json:"resource_utilization"`
	ScalingHistory        []ScalingEvent         `json:"scaling_history"`
	Uptime                time.Duration          `json:"uptime"`
	MTTR                  time.Duration          `json:"mttr"` // Mean Time To Recovery
	Availability          float64                `json:"availability"`
}

// ResourceUtilization tracks resource usage across the pipeline
type ResourceUtilization struct {
	CPUUsage       float64 `json:"cpu_usage"`
	MemoryUsage    float64 `json:"memory_usage"`
	NetworkIO      float64 `json:"network_io"`
	DiskIO         float64 `json:"disk_io"`
	ActiveWorkers  int     `json:"active_workers"`
	QueueLength    int     `json:"queue_length"`
	Throughput     float64 `json:"throughput"`
	ErrorRate      float64 `json:"error_rate"`
}

// ScalingEvent represents a scaling event in the pipeline
type ScalingEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Direction   string    `json:"direction"`
	OldWorkers  int       `json:"old_workers"`
	NewWorkers  int       `json:"new_workers"`
	Reason      string    `json:"reason"`
	TriggeredBy string    `json:"triggered_by"`
}

// HealthDashboard provides real-time health dashboard data
type HealthDashboard struct {
	metrics      *SelfHealingMetrics
	startTime    time.Time
	scalingHistory []ScalingEvent
	mutex        sync.RWMutex
}

// NewHealthDashboard creates a new health dashboard
func NewHealthDashboard(metrics *SelfHealingMetrics) *HealthDashboard {
	return &HealthDashboard{
		metrics:        metrics,
		startTime:      time.Now(),
		scalingHistory: make([]ScalingEvent, 0),
	}
}

// AddScalingEvent adds a scaling event to the history
func (hd *HealthDashboard) AddScalingEvent(event ScalingEvent) {
	hd.mutex.Lock()
	defer hd.mutex.Unlock()
	
	hd.scalingHistory = append(hd.scalingHistory, event)
	
	// Keep only last 100 events
	if len(hd.scalingHistory) > 100 {
		hd.scalingHistory = hd.scalingHistory[1:]
	}
}

// GetHealthMetrics returns comprehensive health metrics
func (hd *HealthDashboard) GetHealthMetrics(componentHealth map[string]interface{}, cbStates map[string]interface{}) PipelineHealthMetrics {
	hd.mutex.RLock()
	defer hd.mutex.RUnlock()
	
	// Calculate overall health
	overallHealth := "healthy"
	componentScores := make(map[string]float64)
	
	for componentID, health := range componentHealth {
		if healthMap, ok := health.(map[string]interface{}); ok {
			if status, exists := healthMap["status"]; exists {
				if statusStr, ok := status.(string); ok {
					score := hd.healthStatusToScore(statusStr)
					componentScores[componentID] = score
					if score < 0.7 && overallHealth == "healthy" {
						overallHealth = "degraded"
					}
					if score < 0.4 {
						overallHealth = "critical"
					}
				}
			}
		}
	}
	
	// Convert circuit breaker states
	cbStateMap := make(map[string]string)
	for name, state := range cbStates {
		if stateStr, ok := state.(string); ok {
			cbStateMap[name] = stateStr
		}
	}
	
	return PipelineHealthMetrics{
		OverallHealth:         overallHealth,
		ComponentHealthScores: componentScores,
		ActiveHealingActions:  0, // Would be calculated from active actions
		TotalHealingActions:   0, // Would be calculated from metrics
		CircuitBreakerStates:  cbStateMap,
		ResourceUtilization:   hd.calculateResourceUtilization(),
		ScalingHistory:        hd.scalingHistory,
		Uptime:                time.Since(hd.startTime),
		MTTR:                  hd.calculateMTTR(),
		Availability:          hd.calculateAvailability(),
	}
}

// healthStatusToScore converts health status to numerical score
func (hd *HealthDashboard) healthStatusToScore(status string) float64 {
	switch status {
	case "HEALTHY":
		return 1.0
	case "DEGRADED":
		return 0.7
	case "UNHEALTHY":
		return 0.4
	case "CRITICAL":
		return 0.1
	default:
		return 0.5
	}
}

// calculateResourceUtilization calculates current resource utilization
func (hd *HealthDashboard) calculateResourceUtilization() ResourceUtilization {
	// This would integrate with actual resource monitoring
	// For now, return simulated values
	return ResourceUtilization{
		CPUUsage:      0.45,
		MemoryUsage:   0.62,
		NetworkIO:     0.33,
		DiskIO:        0.28,
		ActiveWorkers: 8,
		QueueLength:   15,
		Throughput:    125.5,
		ErrorRate:     0.02,
	}
}

// calculateMTTR calculates Mean Time To Recovery
func (hd *HealthDashboard) calculateMTTR() time.Duration {
	// This would be calculated from actual recovery events
	// For now, return a simulated value
	return 2 * time.Minute
}

// calculateAvailability calculates system availability percentage
func (hd *HealthDashboard) calculateAvailability() float64 {
	// This would be calculated from actual uptime/downtime data
	// For now, return a simulated value
	return 99.8
}

// AlertManager handles alerting for self-healing events
type AlertManager struct {
	logger    *logrus.Logger
	alertChan chan Alert
	mutex     sync.RWMutex
}

// Alert represents a self-healing alert
type Alert struct {
	ID          string                 `json:"id"`
	Severity    AlertSeverity          `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	ComponentID string                 `json:"component_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

// AlertSeverity defines alert severity levels
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// NewAlertManager creates a new alert manager
func NewAlertManager(logger *logrus.Logger) *AlertManager {
	return &AlertManager{
		logger:    logger,
		alertChan: make(chan Alert, 1000),
	}
}

// SendAlert sends an alert
func (am *AlertManager) SendAlert(alert Alert) {
	select {
	case am.alertChan <- alert:
		am.logger.WithFields(logrus.Fields{
			"alert_id": alert.ID,
			"severity": alert.Severity,
			"component_id": alert.ComponentID,
			"title": alert.Title,
		}).Info("Alert sent")
	default:
		am.logger.Warn("Alert channel full, dropping alert")
	}
}

// GetAlerts returns pending alerts
func (am *AlertManager) GetAlerts() []Alert {
	alerts := make([]Alert, 0)
	
	for {
		select {
		case alert := <-am.alertChan:
			alerts = append(alerts, alert)
		default:
			return alerts
		}
	}
}
