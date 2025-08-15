package pipeline

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/resilience"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/sirupsen/logrus"
)

// HealthStatus represents the health state of a pipeline component
type HealthStatus int32

const (
	HealthStatusHealthy HealthStatus = iota
	HealthStatusDegraded
	HealthStatusUnhealthy
	HealthStatusCritical
)

func (h HealthStatus) String() string {
	switch h {
	case HealthStatusHealthy:
		return "HEALTHY"
	case HealthStatusDegraded:
		return "DEGRADED"
	case HealthStatusUnhealthy:
		return "UNHEALTHY"
	case HealthStatusCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// SelfHealingConfig defines configuration for self-healing capabilities
type SelfHealingConfig struct {
	Enabled                bool          `json:"enabled"`
	HealthCheckInterval    time.Duration `json:"health_check_interval"`
	FailureThreshold       int           `json:"failure_threshold"`
	RecoveryThreshold      int           `json:"recovery_threshold"`
	AutoRestartEnabled     bool          `json:"auto_restart_enabled"`
	CircuitBreakerEnabled  bool          `json:"circuit_breaker_enabled"`
	AdaptiveScalingEnabled bool          `json:"adaptive_scaling_enabled"`
	MaxWorkers             int           `json:"max_workers"`
	MinWorkers             int           `json:"min_workers"`
	ScalingCooldown        time.Duration `json:"scaling_cooldown"`
	MemoryThreshold        float64       `json:"memory_threshold"`
	CPUThreshold           float64       `json:"cpu_threshold"`
}

// DefaultSelfHealingConfig returns sensible defaults for self-healing
func DefaultSelfHealingConfig() SelfHealingConfig {
	return SelfHealingConfig{
		Enabled:                true,
		HealthCheckInterval:    30 * time.Second,
		FailureThreshold:       3,
		RecoveryThreshold:      5,
		AutoRestartEnabled:     true,
		CircuitBreakerEnabled:  true,
		AdaptiveScalingEnabled: true,
		MaxWorkers:            20,
		MinWorkers:            2,
		ScalingCooldown:       5 * time.Minute,
		MemoryThreshold:       0.8, // 80%
		CPUThreshold:          0.7, // 70%
	}
}

// ComponentHealth tracks health of individual pipeline components
type ComponentHealth struct {
	ComponentID       string        `json:"component_id"`
	Status           HealthStatus  `json:"status"`
	LastHealthCheck  time.Time     `json:"last_health_check"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	ConsecutiveSuccesses int       `json:"consecutive_successes"`
	ErrorRate        float64       `json:"error_rate"`
	Latency          time.Duration `json:"latency"`
	Throughput       float64       `json:"throughput"`
	ResourceUsage    ResourceUsage `json:"resource_usage"`
	LastError        string        `json:"last_error,omitempty"`
}

// ResourceUsage tracks resource consumption of components
type ResourceUsage struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	MemoryBytes   int64   `json:"memory_bytes"`
	Goroutines    int     `json:"goroutines"`
}

// HealingAction represents an action taken by the self-healing system
type HealingAction struct {
	ID          string                 `json:"id"`
	Type        HealingActionType      `json:"type"`
	ComponentID string                 `json:"component_id"`
	Reason      string                 `json:"reason"`
	Timestamp   time.Time              `json:"timestamp"`
	Success     bool                   `json:"success"`
	Details     map[string]interface{} `json:"details"`
}

type HealingActionType string

const (
	HealingActionRestart        HealingActionType = "restart"
	HealingActionScale          HealingActionType = "scale"
	HealingActionCircuitBreaker HealingActionType = "circuit_breaker"
	HealingActionReroute        HealingActionType = "reroute"
	HealingActionIsolate        HealingActionType = "isolate"
	HealingActionReconfigure    HealingActionType = "reconfigure"
)

// SelfHealingPipeline extends AsyncPipeline with self-healing capabilities
type SelfHealingPipeline struct {
	*AsyncPipeline
	config          SelfHealingConfig
	componentHealth map[string]*ComponentHealth
	circuitBreakers map[string]*resilience.CircuitBreaker
	healingActions  []HealingAction
	logger          *logrus.Logger
	metricsCollector *monitoring.MetricsCollector
	mutex           sync.RWMutex
	lastScalingTime time.Time
	running         int64
}

// NewSelfHealingPipeline creates a new self-healing pipeline
func NewSelfHealingPipeline(
	pipelineConfig PipelineConfig,
	selfHealingConfig SelfHealingConfig,
	stages []PipelineStage,
	logger *logrus.Logger,
	metricsCollector *monitoring.MetricsCollector,
) *SelfHealingPipeline {
	basePipeline := NewAsyncPipeline(pipelineConfig, stages, nil)
	
	shp := &SelfHealingPipeline{
		AsyncPipeline:    basePipeline,
		config:           selfHealingConfig,
		componentHealth:  make(map[string]*ComponentHealth),
		circuitBreakers:  make(map[string]*resilience.CircuitBreaker),
		healingActions:   make([]HealingAction, 0),
		logger:           logger,
		metricsCollector: metricsCollector,
		lastScalingTime:  time.Now(),
	}
	
	// Initialize component health tracking
	for i, stage := range stages {
		componentID := fmt.Sprintf("stage_%d_%s", i, stage.Name())
		shp.componentHealth[componentID] = &ComponentHealth{
			ComponentID:       componentID,
			Status:           HealthStatusHealthy,
			LastHealthCheck:  time.Now(),
			ResourceUsage:    ResourceUsage{},
		}
		
		// Initialize circuit breaker if enabled
		if selfHealingConfig.CircuitBreakerEnabled {
			cbConfig := resilience.DefaultConfig(componentID)
			cbConfig.OnStateChange = shp.onCircuitBreakerStateChange
			shp.circuitBreakers[componentID] = resilience.NewCircuitBreaker(cbConfig)
		}
	}
	
	// Start self-healing monitoring if enabled
	if selfHealingConfig.Enabled {
		atomic.StoreInt64(&shp.running, 1)
		go shp.healthMonitor()
		go shp.adaptiveScaler()
	}
	
	return shp
}

// Start starts the self-healing pipeline
func (shp *SelfHealingPipeline) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt64(&shp.running, 0, 1) {
		return fmt.Errorf("pipeline is already running")
	}
	
	shp.logger.Info("Starting self-healing pipeline")
	
	// Start monitoring goroutines
	if shp.config.Enabled {
		go shp.healthMonitor()
		go shp.adaptiveScaler()
	}
	
	return nil
}

// Stop gracefully stops the self-healing pipeline
func (shp *SelfHealingPipeline) Stop(timeout time.Duration) error {
	if !atomic.CompareAndSwapInt64(&shp.running, 1, 0) {
		return fmt.Errorf("pipeline is not running")
	}
	
	shp.logger.Info("Stopping self-healing pipeline")
	
	// Stop base pipeline
	return shp.AsyncPipeline.Shutdown(timeout)
}

// healthMonitor continuously monitors component health
func (shp *SelfHealingPipeline) healthMonitor() {
	ticker := time.NewTicker(shp.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for atomic.LoadInt64(&shp.running) == 1 {
		select {
		case <-ticker.C:
			shp.performHealthCheck()
		case <-shp.ctx.Done():
			return
		}
	}
}

// performHealthCheck checks health of all components and triggers healing actions
func (shp *SelfHealingPipeline) performHealthCheck() {
	shp.mutex.Lock()
	defer shp.mutex.Unlock()
	
	for componentID, health := range shp.componentHealth {
		// Update resource usage
		shp.updateResourceUsage(health)
		
		// Check component health
		previousStatus := health.Status
		currentStatus := shp.assessComponentHealth(health)
		
		if currentStatus != previousStatus {
			shp.logger.WithFields(logrus.Fields{
				"component_id": componentID,
				"previous_status": previousStatus.String(),
				"current_status": currentStatus.String(),
			}).Info("Component health status changed")
			
			health.Status = currentStatus
			
			// Trigger healing actions if needed
			shp.triggerHealingActions(componentID, health)
		}
		
		health.LastHealthCheck = time.Now()
	}
}

// updateResourceUsage updates resource usage metrics for a component
func (shp *SelfHealingPipeline) updateResourceUsage(health *ComponentHealth) {
	// This would integrate with actual resource monitoring
	// For now, we'll simulate based on pipeline metrics
	metrics := shp.GetMetrics()
	
	health.ResourceUsage.MemoryBytes = metrics.MemoryUsage
	health.ResourceUsage.MemoryPercent = float64(metrics.MemoryUsage) / float64(shp.config.MaxWorkers*1024*1024*100) // Rough estimation
	health.ResourceUsage.CPUPercent = float64(metrics.ActiveWorkers) / float64(shp.config.MaxWorkers)
	health.ResourceUsage.Goroutines = int(metrics.ActiveWorkers)
	
	// Calculate error rate and throughput
	if metrics.ItemsProcessed > 0 {
		health.ErrorRate = float64(metrics.ItemsFailed) / float64(metrics.ItemsProcessed)
		health.Throughput = metrics.ThroughputPerSec
	}
}

// assessComponentHealth determines the health status of a component
func (shp *SelfHealingPipeline) assessComponentHealth(health *ComponentHealth) HealthStatus {
	// Check error rate
	if health.ErrorRate > 0.5 {
		return HealthStatusCritical
	}
	if health.ErrorRate > 0.2 {
		return HealthStatusUnhealthy
	}
	if health.ErrorRate > 0.1 {
		return HealthStatusDegraded
	}
	
	// Check resource usage
	if health.ResourceUsage.MemoryPercent > 0.9 || health.ResourceUsage.CPUPercent > 0.9 {
		return HealthStatusCritical
	}
	if health.ResourceUsage.MemoryPercent > shp.config.MemoryThreshold || health.ResourceUsage.CPUPercent > shp.config.CPUThreshold {
		return HealthStatusDegraded
	}
	
	// Check consecutive failures
	if health.ConsecutiveFailures >= shp.config.FailureThreshold {
		return HealthStatusUnhealthy
	}
	
	return HealthStatusHealthy
}

// triggerHealingActions triggers appropriate healing actions based on component health
func (shp *SelfHealingPipeline) triggerHealingActions(componentID string, health *ComponentHealth) {
	switch health.Status {
	case HealthStatusCritical:
		shp.handleCriticalHealth(componentID, health)
	case HealthStatusUnhealthy:
		shp.handleUnhealthyComponent(componentID, health)
	case HealthStatusDegraded:
		shp.handleDegradedComponent(componentID, health)
	case HealthStatusHealthy:
		shp.handleHealthyComponent(componentID, health)
	}
}

// handleCriticalHealth handles components in critical state
func (shp *SelfHealingPipeline) handleCriticalHealth(componentID string, health *ComponentHealth) {
	shp.logger.WithField("component_id", componentID).Error("Component in critical state, taking emergency actions")
	
	// Isolate component
	action := HealingAction{
		ID:          fmt.Sprintf("isolate_%s_%d", componentID, time.Now().Unix()),
		Type:        HealingActionIsolate,
		ComponentID: componentID,
		Reason:      "Critical health status detected",
		Timestamp:   time.Now(),
		Details: map[string]interface{}{
			"error_rate": health.ErrorRate,
			"memory_usage": health.ResourceUsage.MemoryPercent,
			"cpu_usage": health.ResourceUsage.CPUPercent,
		},
	}
	
	// Execute isolation (circuit breaker)
	if cb, exists := shp.circuitBreakers[componentID]; exists && shp.config.CircuitBreakerEnabled {
		// Force circuit breaker to open
		cb.Execute(func() error {
			return fmt.Errorf("component isolated due to critical health")
		})
		action.Success = true
	} else {
		action.Success = false
	}
	
	shp.healingActions = append(shp.healingActions, action)
	
	// Trigger restart if auto-restart is enabled
	if shp.config.AutoRestartEnabled {
		shp.restartComponent(componentID, "Critical health status")
	}
}

// handleUnhealthyComponent handles unhealthy components
func (shp *SelfHealingPipeline) handleUnhealthyComponent(componentID string, health *ComponentHealth) {
	shp.logger.WithField("component_id", componentID).Warn("Component unhealthy, applying healing actions")
	
	// Try restart first
	if shp.config.AutoRestartEnabled {
		shp.restartComponent(componentID, "Unhealthy component detected")
	}
	
	// If resource constraints, try scaling
	if health.ResourceUsage.MemoryPercent > shp.config.MemoryThreshold ||
	   health.ResourceUsage.CPUPercent > shp.config.CPUThreshold {
		shp.triggerScaling(componentID, "Resource constraints detected")
	}
}

// handleDegradedComponent handles degraded components
func (shp *SelfHealingPipeline) handleDegradedComponent(componentID string, health *ComponentHealth) {
	shp.logger.WithField("component_id", componentID).Info("Component degraded, monitoring closely")
	
	// Increase monitoring frequency for degraded components
	// This could be implemented by adjusting health check intervals
	
	// Consider preemptive scaling if resource usage is high
	if health.ResourceUsage.MemoryPercent > 0.6 || health.ResourceUsage.CPUPercent > 0.6 {
		shp.triggerScaling(componentID, "Preemptive scaling for degraded component")
	}
}

// handleHealthyComponent handles healthy components
func (shp *SelfHealingPipeline) handleHealthyComponent(componentID string, health *ComponentHealth) {
	// Reset consecutive failure count
	health.ConsecutiveFailures = 0
	health.ConsecutiveSuccesses++
	
	// Consider scaling down if resource usage is consistently low
	if health.ConsecutiveSuccesses >= shp.config.RecoveryThreshold &&
	   health.ResourceUsage.MemoryPercent < 0.3 &&
	   health.ResourceUsage.CPUPercent < 0.3 {
		shp.considerScaleDown(componentID, "Low resource usage detected")
	}
}

// restartComponent restarts a pipeline component
func (shp *SelfHealingPipeline) restartComponent(componentID, reason string) {
	action := HealingAction{
		ID:          fmt.Sprintf("restart_%s_%d", componentID, time.Now().Unix()),
		Type:        HealingActionRestart,
		ComponentID: componentID,
		Reason:      reason,
		Timestamp:   time.Now(),
	}
	
	shp.logger.WithFields(logrus.Fields{
		"component_id": componentID,
		"reason": reason,
	}).Info("Restarting component")
	
	// Implementation would restart the specific component
	// For this demo, we'll simulate by resetting health metrics
	if health, exists := shp.componentHealth[componentID]; exists {
		health.ConsecutiveFailures = 0
		health.ErrorRate = 0
		health.LastError = ""
		action.Success = true
	} else {
		action.Success = false
	}
	
	shp.healingActions = append(shp.healingActions, action)
}

// adaptiveScaler handles adaptive scaling of the pipeline
func (shp *SelfHealingPipeline) adaptiveScaler() {
	if !shp.config.AdaptiveScalingEnabled {
		return
	}
	
	ticker := time.NewTicker(time.Minute) // Check every minute
	defer ticker.Stop()
	
	for atomic.LoadInt64(&shp.running) == 1 {
		select {
		case <-ticker.C:
			shp.evaluateScaling()
		case <-shp.ctx.Done():
			return
		}
	}
}

// evaluateScaling evaluates whether scaling is needed
func (shp *SelfHealingPipeline) evaluateScaling() {
	// Check if we're in cooldown period
	if time.Since(shp.lastScalingTime) < shp.config.ScalingCooldown {
		return
	}
	
	metrics := shp.GetMetrics()
	currentWorkers := int(metrics.ActiveWorkers)
	queueLength := int(metrics.QueueLength)
	
	// Scale up conditions
	if queueLength > currentWorkers*2 && currentWorkers < shp.config.MaxWorkers {
		shp.scaleUp("High queue length detected")
		return
	}
	
	// Check resource usage across all components
	avgCPU, avgMemory := shp.getAverageResourceUsage()
	if (avgCPU > shp.config.CPUThreshold || avgMemory > shp.config.MemoryThreshold) &&
	   currentWorkers < shp.config.MaxWorkers {
		shp.scaleUp("High resource usage detected")
		return
	}
	
	// Scale down conditions
	if queueLength == 0 && avgCPU < 0.3 && avgMemory < 0.3 && currentWorkers > shp.config.MinWorkers {
		shp.scaleDown("Low resource usage and empty queue")
	}
}

// getAverageResourceUsage calculates average resource usage across components
func (shp *SelfHealingPipeline) getAverageResourceUsage() (float64, float64) {
	shp.mutex.RLock()
	defer shp.mutex.RUnlock()
	
	if len(shp.componentHealth) == 0 {
		return 0, 0
	}
	
	totalCPU := 0.0
	totalMemory := 0.0
	
	for _, health := range shp.componentHealth {
		totalCPU += health.ResourceUsage.CPUPercent
		totalMemory += health.ResourceUsage.MemoryPercent
	}
	
	count := float64(len(shp.componentHealth))
	return totalCPU / count, totalMemory / count
}

// triggerScaling triggers scaling action for a specific component
func (shp *SelfHealingPipeline) triggerScaling(componentID, reason string) {
	if time.Since(shp.lastScalingTime) < shp.config.ScalingCooldown {
		return
	}
	
	metrics := shp.GetMetrics()
	currentWorkers := int(metrics.ActiveWorkers)
	
	if currentWorkers < shp.config.MaxWorkers {
		shp.scaleUp(reason)
	}
}

// considerScaleDown considers scaling down for a specific component
func (shp *SelfHealingPipeline) considerScaleDown(componentID, reason string) {
	if time.Since(shp.lastScalingTime) < shp.config.ScalingCooldown {
		return
	}
	
	metrics := shp.GetMetrics()
	currentWorkers := int(metrics.ActiveWorkers)
	
	if currentWorkers > shp.config.MinWorkers {
		shp.scaleDown(reason)
	}
}

// scaleUp increases the number of workers
func (shp *SelfHealingPipeline) scaleUp(reason string) {
	action := HealingAction{
		ID:        fmt.Sprintf("scale_up_%d", time.Now().Unix()),
		Type:      HealingActionScale,
		Reason:    reason,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"direction": "up",
			"current_workers": len(shp.workers),
		},
	}
	
	shp.logger.WithField("reason", reason).Info("Scaling up pipeline workers")
	
	// Implementation would add more workers to the pipeline
	// For this demo, we'll simulate successful scaling
	action.Success = true
	shp.lastScalingTime = time.Now()
	
	shp.healingActions = append(shp.healingActions, action)
}

// scaleDown decreases the number of workers
func (shp *SelfHealingPipeline) scaleDown(reason string) {
	action := HealingAction{
		ID:        fmt.Sprintf("scale_down_%d", time.Now().Unix()),
		Type:      HealingActionScale,
		Reason:    reason,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"direction": "down",
			"current_workers": len(shp.workers),
		},
	}
	
	shp.logger.WithField("reason", reason).Info("Scaling down pipeline workers")
	
	// Implementation would remove workers from the pipeline
	// For this demo, we'll simulate successful scaling
	action.Success = true
	shp.lastScalingTime = time.Now()
	
	shp.healingActions = append(shp.healingActions, action)
}

// onCircuitBreakerStateChange handles circuit breaker state changes
func (shp *SelfHealingPipeline) onCircuitBreakerStateChange(name string, from, to resilience.CircuitState) {
	action := HealingAction{
		ID:          fmt.Sprintf("cb_%s_%d", name, time.Now().Unix()),
		Type:        HealingActionCircuitBreaker,
		ComponentID: name,
		Reason:      fmt.Sprintf("Circuit breaker state changed from %s to %s", from, to),
		Timestamp:   time.Now(),
		Success:     true,
		Details: map[string]interface{}{
			"from_state": from.String(),
			"to_state":   to.String(),
		},
	}
	
	shp.logger.WithFields(logrus.Fields{
		"component": name,
		"from_state": from.String(),
		"to_state": to.String(),
	}).Info("Circuit breaker state changed")
	
	shp.healingActions = append(shp.healingActions, action)
	
	// Update component health based on circuit breaker state
	shp.mutex.Lock()
	if health, exists := shp.componentHealth[name]; exists {
		switch to {
		case resilience.StateOpen:
			health.Status = HealthStatusCritical
			health.ConsecutiveFailures++
		case resilience.StateHalfOpen:
			health.Status = HealthStatusDegraded
		case resilience.StateClosed:
			health.Status = HealthStatusHealthy
			health.ConsecutiveFailures = 0
			health.ConsecutiveSuccesses++
		}
	}
	shp.mutex.Unlock()
}

// GetComponentHealth returns the health status of all components
func (shp *SelfHealingPipeline) GetComponentHealth() map[string]ComponentHealth {
	shp.mutex.RLock()
	defer shp.mutex.RUnlock()
	
	result := make(map[string]ComponentHealth)
	for id, health := range shp.componentHealth {
		result[id] = *health
	}
	return result
}

// GetHealingActions returns the history of healing actions
func (shp *SelfHealingPipeline) GetHealingActions(limit int) []HealingAction {
	shp.mutex.RLock()
	defer shp.mutex.RUnlock()
	
	if limit <= 0 || limit > len(shp.healingActions) {
		limit = len(shp.healingActions)
	}
	
	// Return most recent actions
	start := len(shp.healingActions) - limit
	if start < 0 {
		start = 0
	}
	
	return shp.healingActions[start:]
}

// GetOverallHealth returns the overall health status of the pipeline
func (shp *SelfHealingPipeline) GetOverallHealth() HealthStatus {
	shp.mutex.RLock()
	defer shp.mutex.RUnlock()
	
	if len(shp.componentHealth) == 0 {
		return HealthStatusUnknown
	}
	
	// Determine overall health based on worst component
	worstStatus := HealthStatusHealthy
	for _, health := range shp.componentHealth {
		if health.Status > worstStatus {
			worstStatus = health.Status
		}
	}
	
	return worstStatus
}

// ReportComponentFailure manually reports a component failure
func (shp *SelfHealingPipeline) ReportComponentFailure(componentID, errorMsg string) {
	shp.mutex.Lock()
	defer shp.mutex.Unlock()
	
	if health, exists := shp.componentHealth[componentID]; exists {
		health.ConsecutiveFailures++
		health.ConsecutiveSuccesses = 0
		health.LastError = errorMsg
		
		// Trigger immediate health assessment
		go shp.performHealthCheck()
	}
}

// ReportComponentSuccess manually reports a component success
func (shp *SelfHealingPipeline) ReportComponentSuccess(componentID string) {
	shp.mutex.Lock()
	defer shp.mutex.Unlock()
	
	if health, exists := shp.componentHealth[componentID]; exists {
		health.ConsecutiveSuccesses++
		health.LastError = ""
	}
}

// GetCircuitBreakerStatus returns the status of all circuit breakers
func (shp *SelfHealingPipeline) GetCircuitBreakerStatus() map[string]resilience.CircuitState {
	status := make(map[string]resilience.CircuitState)
	for name, cb := range shp.circuitBreakers {
		status[name] = cb.State()
	}
	return status
}
