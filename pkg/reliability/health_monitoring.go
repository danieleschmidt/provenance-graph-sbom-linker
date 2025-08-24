package reliability

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// HealthMonitoringSystem provides comprehensive system health monitoring
type HealthMonitoringSystem struct {
	logger         *logrus.Logger
	config         *HealthMonitoringConfig
	monitors       map[string]HealthMonitor
	aggregator     *HealthAggregator
	alertManager   *AlertManager
	mu            sync.RWMutex
	running       int32
	stopChan      chan struct{}
}

// HealthMonitoringConfig configures the health monitoring system
type HealthMonitoringConfig struct {
	CheckInterval           time.Duration              `json:"check_interval"`
	AlertingEnabled        bool                       `json:"alerting_enabled"`
	MetricsRetention       time.Duration              `json:"metrics_retention"`
	FailureThreshold       int                        `json:"failure_threshold"`
	RecoveryThreshold      int                        `json:"recovery_threshold"`
	ComponentTimeout       time.Duration              `json:"component_timeout"`
	AlertCooldown          time.Duration              `json:"alert_cooldown"`
	EnablePredictiveHealth bool                       `json:"enable_predictive_health"`
	CustomChecks          map[string]CustomHealthCheck `json:"custom_checks"`
}

// HealthMonitor defines interface for component health monitoring
type HealthMonitor interface {
	GetName() string
	CheckHealth(ctx context.Context) *HealthStatus
	GetHealthHistory() []*HealthStatus
	IsHealthy() bool
	GetMetrics() *HealthMetrics
}

// HealthStatus represents the health status of a component
type HealthStatus struct {
	ComponentName    string                 `json:"component_name"`
	Status          HealthState            `json:"status"`
	Message         string                 `json:"message"`
	Timestamp       time.Time              `json:"timestamp"`
	ResponseTime    time.Duration          `json:"response_time"`
	CheckedBy       string                 `json:"checked_by"`
	Dependencies    []DependencyStatus     `json:"dependencies,omitempty"`
	Metrics         map[string]interface{} `json:"metrics,omitempty"`
	Details         HealthDetails          `json:"details,omitempty"`
	SeverityLevel   Severity              `json:"severity_level"`
	RecoveryActions []string              `json:"recovery_actions,omitempty"`
}

// HealthState represents the current state of a component
type HealthState string

const (
	HealthStateHealthy    HealthState = "HEALTHY"
	HealthStateDegraded   HealthState = "DEGRADED"
	HealthStateUnhealthy  HealthState = "UNHEALTHY"
	HealthStateCritical   HealthState = "CRITICAL"
	HealthStateUnknown    HealthState = "UNKNOWN"
)

// Severity represents the severity level of a health issue
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// DependencyStatus represents the status of a dependency
type DependencyStatus struct {
	Name         string      `json:"name"`
	Status       HealthState `json:"status"`
	ResponseTime time.Duration `json:"response_time"`
	LastChecked  time.Time   `json:"last_checked"`
	ErrorMessage string      `json:"error_message,omitempty"`
}

// HealthDetails provides detailed health information
type HealthDetails struct {
	CPUUsage        float64   `json:"cpu_usage,omitempty"`
	MemoryUsage     float64   `json:"memory_usage,omitempty"`
	DiskUsage       float64   `json:"disk_usage,omitempty"`
	NetworkLatency  time.Duration `json:"network_latency,omitempty"`
	ActiveConnections int     `json:"active_connections,omitempty"`
	QueueDepth      int       `json:"queue_depth,omitempty"`
	ErrorRate       float64   `json:"error_rate,omitempty"`
	Throughput      float64   `json:"throughput,omitempty"`
	CustomMetrics   map[string]interface{} `json:"custom_metrics,omitempty"`
}

// HealthMetrics aggregates health metrics over time
type HealthMetrics struct {
	ComponentName       string        `json:"component_name"`
	UptimePercentage   float64       `json:"uptime_percentage"`
	MeanResponseTime   time.Duration `json:"mean_response_time"`
	P95ResponseTime    time.Duration `json:"p95_response_time"`
	P99ResponseTime    time.Duration `json:"p99_response_time"`
	FailureCount       int64         `json:"failure_count"`
	RecoveryCount      int64         `json:"recovery_count"`
	LastFailureTime    *time.Time    `json:"last_failure_time,omitempty"`
	LastRecoveryTime   *time.Time    `json:"last_recovery_time,omitempty"`
	TotalChecks        int64         `json:"total_checks"`
	ConsecutiveFailures int64        `json:"consecutive_failures"`
	HealthScore        float64       `json:"health_score"`
}

// SystemHealthReport provides overall system health
type SystemHealthReport struct {
	OverallStatus        HealthState                    `json:"overall_status"`
	HealthScore          float64                       `json:"health_score"`
	ComponentStatuses    map[string]*HealthStatus      `json:"component_statuses"`
	CriticalIssues       []HealthIssue                `json:"critical_issues"`
	Warnings            []HealthIssue                `json:"warnings"`
	SystemMetrics       *SystemMetrics               `json:"system_metrics"`
	Recommendations     []string                     `json:"recommendations"`
	PredictiveInsights  []PredictiveInsight          `json:"predictive_insights"`
	GeneratedAt         time.Time                    `json:"generated_at"`
	NextCheckAt         time.Time                    `json:"next_check_at"`
}

// HealthIssue represents a health-related issue
type HealthIssue struct {
	ComponentName string    `json:"component_name"`
	IssueType     string    `json:"issue_type"`
	Severity      Severity  `json:"severity"`
	Description   string    `json:"description"`
	DetectedAt    time.Time `json:"detected_at"`
	Impact        string    `json:"impact"`
	Resolution    string    `json:"resolution,omitempty"`
}

// SystemMetrics provides system-level metrics
type SystemMetrics struct {
	TotalComponents     int                 `json:"total_components"`
	HealthyComponents   int                 `json:"healthy_components"`
	DegradedComponents  int                 `json:"degraded_components"`
	UnhealthyComponents int                 `json:"unhealthy_components"`
	CriticalComponents  int                 `json:"critical_components"`
	AverageResponseTime time.Duration       `json:"average_response_time"`
	SystemLoad          float64             `json:"system_load"`
	ResourceUtilization ResourceUtilization `json:"resource_utilization"`
}

// ResourceUtilization tracks system resource usage
type ResourceUtilization struct {
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"memory"`
	Disk    float64 `json:"disk"`
	Network float64 `json:"network"`
}

// PredictiveInsight provides predictive health insights
type PredictiveInsight struct {
	ComponentName       string    `json:"component_name"`
	PredictedState      HealthState `json:"predicted_state"`
	Confidence         float64   `json:"confidence"`
	TimeToEvent        time.Duration `json:"time_to_event"`
	Description        string    `json:"description"`
	RecommendedActions []string  `json:"recommended_actions"`
}

// CustomHealthCheck allows defining custom health checks
type CustomHealthCheck struct {
	Name        string        `json:"name"`
	URL         string        `json:"url,omitempty"`
	Command     string        `json:"command,omitempty"`
	Expected    interface{}   `json:"expected,omitempty"`
	Timeout     time.Duration `json:"timeout"`
	Interval    time.Duration `json:"interval"`
	Enabled     bool          `json:"enabled"`
}

// HealthAggregator aggregates health information from multiple monitors
type HealthAggregator struct {
	healthHistory map[string][]*HealthStatus
	metrics       map[string]*HealthMetrics
	mu           sync.RWMutex
}

// AlertManager handles health-related alerts
type AlertManager struct {
	config           *AlertConfig
	activeAlerts     map[string]*Alert
	alertHistory     []*Alert
	lastAlertTime    map[string]time.Time
	mu              sync.RWMutex
}

// AlertConfig configures alerting behavior
type AlertConfig struct {
	Enabled          bool                    `json:"enabled"`
	Channels         []AlertChannel          `json:"channels"`
	Cooldown         time.Duration           `json:"cooldown"`
	Escalation       EscalationPolicy        `json:"escalation"`
	Filters          []AlertFilter          `json:"filters"`
}

// AlertChannel defines how alerts are delivered
type AlertChannel struct {
	Type     string                 `json:"type"`
	Config   map[string]interface{} `json:"config"`
	Enabled  bool                   `json:"enabled"`
}

// EscalationPolicy defines alert escalation rules
type EscalationPolicy struct {
	Levels          []EscalationLevel `json:"levels"`
	MaxEscalations  int               `json:"max_escalations"`
}

// EscalationLevel defines escalation behavior at each level
type EscalationLevel struct {
	WaitTime      time.Duration  `json:"wait_time"`
	Channels      []string       `json:"channels"`
	RequiredState HealthState    `json:"required_state"`
}

// AlertFilter filters which alerts should be sent
type AlertFilter struct {
	ComponentName string      `json:"component_name"`
	Severity     Severity    `json:"severity"`
	State        HealthState `json:"state"`
	Action       string      `json:"action"`
}

// Alert represents a health alert
type Alert struct {
	ID           string      `json:"id"`
	ComponentName string     `json:"component_name"`
	Severity     Severity    `json:"severity"`
	State        HealthState `json:"state"`
	Message      string      `json:"message"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
	ResolvedAt   *time.Time  `json:"resolved_at,omitempty"`
	Escalations  int         `json:"escalations"`
	Acknowledged bool        `json:"acknowledged"`
}

// NewHealthMonitoringSystem creates a new health monitoring system
func NewHealthMonitoringSystem(config *HealthMonitoringConfig, logger *logrus.Logger) *HealthMonitoringSystem {
	return &HealthMonitoringSystem{
		logger:     logger,
		config:     config,
		monitors:   make(map[string]HealthMonitor),
		aggregator: NewHealthAggregator(),
		alertManager: NewAlertManager(&AlertConfig{
			Enabled:  config.AlertingEnabled,
			Cooldown: config.AlertCooldown,
		}),
		stopChan: make(chan struct{}),
	}
}

// NewHealthAggregator creates a new health aggregator
func NewHealthAggregator() *HealthAggregator {
	return &HealthAggregator{
		healthHistory: make(map[string][]*HealthStatus),
		metrics:       make(map[string]*HealthMetrics),
	}
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *AlertConfig) *AlertManager {
	return &AlertManager{
		config:        config,
		activeAlerts:  make(map[string]*Alert),
		alertHistory:  make([]*Alert, 0),
		lastAlertTime: make(map[string]time.Time),
	}
}

// Start starts the health monitoring system
func (hms *HealthMonitoringSystem) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&hms.running, 0, 1) {
		return fmt.Errorf("health monitoring system is already running")
	}

	hms.logger.Info("Starting health monitoring system")

	// Start health check loop
	go hms.healthCheckLoop(ctx)
	
	// Start alert processing
	go hms.alertManager.processAlerts(ctx)

	return nil
}

// Stop stops the health monitoring system
func (hms *HealthMonitoringSystem) Stop() error {
	if !atomic.CompareAndSwapInt32(&hms.running, 1, 0) {
		return fmt.Errorf("health monitoring system is not running")
	}

	close(hms.stopChan)
	hms.logger.Info("Stopped health monitoring system")
	return nil
}

// AddMonitor adds a health monitor for a component
func (hms *HealthMonitoringSystem) AddMonitor(monitor HealthMonitor) {
	hms.mu.Lock()
	defer hms.mu.Unlock()

	name := monitor.GetName()
	hms.monitors[name] = monitor

	hms.logger.WithField("component", name).Info("Added health monitor")
}

// RemoveMonitor removes a health monitor
func (hms *HealthMonitoringSystem) RemoveMonitor(name string) {
	hms.mu.Lock()
	defer hms.mu.Unlock()

	delete(hms.monitors, name)
	hms.aggregator.removeComponent(name)

	hms.logger.WithField("component", name).Info("Removed health monitor")
}

// healthCheckLoop runs the main health checking loop
func (hms *HealthMonitoringSystem) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(hms.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hms.performHealthChecks(ctx)
		case <-ctx.Done():
			return
		case <-hms.stopChan:
			return
		}
	}
}

// performHealthChecks performs health checks on all registered monitors
func (hms *HealthMonitoringSystem) performHealthChecks(ctx context.Context) {
	hms.mu.RLock()
	monitors := make(map[string]HealthMonitor)
	for name, monitor := range hms.monitors {
		monitors[name] = monitor
	}
	hms.mu.RUnlock()

	var wg sync.WaitGroup
	for name, monitor := range monitors {
		wg.Add(1)
		go func(name string, monitor HealthMonitor) {
			defer wg.Done()
			hms.checkComponent(ctx, name, monitor)
		}(name, monitor)
	}

	wg.Wait()
}

// checkComponent performs a health check on a specific component
func (hms *HealthMonitoringSystem) checkComponent(ctx context.Context, name string, monitor HealthMonitor) {
	checkCtx, cancel := context.WithTimeout(ctx, hms.config.ComponentTimeout)
	defer cancel()

	startTime := time.Now()
	status := monitor.CheckHealth(checkCtx)
	status.ResponseTime = time.Since(startTime)

	// Record the health status
	hms.aggregator.recordHealthStatus(status)

	// Check if alerting is needed
	if hms.config.AlertingEnabled {
		hms.evaluateAlerts(status)
	}

	hms.logger.WithFields(logrus.Fields{
		"component":     name,
		"status":        status.Status,
		"response_time": status.ResponseTime,
		"message":       status.Message,
	}).Debug("Health check completed")
}

// evaluateAlerts evaluates if alerts should be triggered
func (hms *HealthMonitoringSystem) evaluateAlerts(status *HealthStatus) {
	switch status.Status {
	case HealthStateUnhealthy, HealthStateCritical:
		hms.alertManager.triggerAlert(status)
	case HealthStateHealthy, HealthStateDegraded:
		hms.alertManager.resolveAlert(status.ComponentName)
	}
}

// GetSystemHealthReport returns a comprehensive system health report
func (hms *HealthMonitoringSystem) GetSystemHealthReport(ctx context.Context) *SystemHealthReport {
	hms.mu.RLock()
	monitors := make(map[string]HealthMonitor)
	for name, monitor := range hms.monitors {
		monitors[name] = monitor
	}
	hms.mu.RUnlock()

	report := &SystemHealthReport{
		ComponentStatuses:   make(map[string]*HealthStatus),
		CriticalIssues:     make([]HealthIssue, 0),
		Warnings:          make([]HealthIssue, 0),
		Recommendations:   make([]string, 0),
		PredictiveInsights: make([]PredictiveInsight, 0),
		GeneratedAt:       time.Now(),
		NextCheckAt:       time.Now().Add(hms.config.CheckInterval),
	}

	// Collect current status from all monitors
	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0
	criticalCount := 0
	totalResponseTime := time.Duration(0)

	for name, monitor := range monitors {
		status := monitor.CheckHealth(ctx)
		report.ComponentStatuses[name] = status

		switch status.Status {
		case HealthStateHealthy:
			healthyCount++
		case HealthStateDegraded:
			degradedCount++
			report.Warnings = append(report.Warnings, HealthIssue{
				ComponentName: name,
				IssueType:     "degraded_performance",
				Severity:      SeverityMedium,
				Description:   status.Message,
				DetectedAt:    status.Timestamp,
				Impact:        "Reduced performance",
			})
		case HealthStateUnhealthy:
			unhealthyCount++
			report.CriticalIssues = append(report.CriticalIssues, HealthIssue{
				ComponentName: name,
				IssueType:     "service_unhealthy",
				Severity:      SeverityHigh,
				Description:   status.Message,
				DetectedAt:    status.Timestamp,
				Impact:        "Service unavailable",
			})
		case HealthStateCritical:
			criticalCount++
			report.CriticalIssues = append(report.CriticalIssues, HealthIssue{
				ComponentName: name,
				IssueType:     "critical_failure",
				Severity:      SeverityCritical,
				Description:   status.Message,
				DetectedAt:    status.Timestamp,
				Impact:        "System instability",
			})
		}

		totalResponseTime += status.ResponseTime
	}

	totalComponents := len(monitors)
	if totalComponents > 0 {
		avgResponseTime := totalResponseTime / time.Duration(totalComponents)
		
		report.SystemMetrics = &SystemMetrics{
			TotalComponents:     totalComponents,
			HealthyComponents:   healthyCount,
			DegradedComponents:  degradedCount,
			UnhealthyComponents: unhealthyCount,
			CriticalComponents:  criticalCount,
			AverageResponseTime: avgResponseTime,
		}
	}

	// Calculate overall status and health score
	if criticalCount > 0 {
		report.OverallStatus = HealthStateCritical
		report.HealthScore = 0.0
	} else if unhealthyCount > 0 {
		report.OverallStatus = HealthStateUnhealthy
		report.HealthScore = 25.0
	} else if degradedCount > 0 {
		report.OverallStatus = HealthStateDegraded
		report.HealthScore = 70.0
	} else {
		report.OverallStatus = HealthStateHealthy
		report.HealthScore = 100.0
	}

	// Generate recommendations
	report.Recommendations = hms.generateRecommendations(report)

	// Generate predictive insights if enabled
	if hms.config.EnablePredictiveHealth {
		report.PredictiveInsights = hms.generatePredictiveInsights(report)
	}

	return report
}

// generateRecommendations generates health recommendations
func (hms *HealthMonitoringSystem) generateRecommendations(report *SystemHealthReport) []string {
	recommendations := make([]string, 0)

	if report.SystemMetrics.CriticalComponents > 0 {
		recommendations = append(recommendations, "Immediate attention required: Critical components detected")
	}

	if report.SystemMetrics.UnhealthyComponents > 0 {
		recommendations = append(recommendations, "Review and restart unhealthy components")
	}

	if report.SystemMetrics.DegradedComponents > 0 {
		recommendations = append(recommendations, "Monitor degraded components closely")
	}

	if report.SystemMetrics.AverageResponseTime > 5*time.Second {
		recommendations = append(recommendations, "High response times detected - consider scaling resources")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "System is operating normally")
	}

	return recommendations
}

// generatePredictiveInsights generates predictive health insights
func (hms *HealthMonitoringSystem) generatePredictiveInsights(report *SystemHealthReport) []PredictiveInsight {
	insights := make([]PredictiveInsight, 0)

	// Simple predictive analysis based on current trends
	for componentName, status := range report.ComponentStatuses {
		if status.Status == HealthStateDegraded {
			insights = append(insights, PredictiveInsight{
				ComponentName:       componentName,
				PredictedState:      HealthStateUnhealthy,
				Confidence:         0.75,
				TimeToEvent:        30 * time.Minute,
				Description:        "Component showing signs of degradation",
				RecommendedActions: []string{"Monitor closely", "Prepare failover"},
			})
		}
	}

	return insights
}

// HealthAggregator methods

// recordHealthStatus records a health status in the aggregator
func (ha *HealthAggregator) recordHealthStatus(status *HealthStatus) {
	ha.mu.Lock()
	defer ha.mu.Unlock()

	componentName := status.ComponentName

	// Add to history
	if _, exists := ha.healthHistory[componentName]; !exists {
		ha.healthHistory[componentName] = make([]*HealthStatus, 0)
	}

	ha.healthHistory[componentName] = append(ha.healthHistory[componentName], status)

	// Keep only recent history (last 100 entries)
	if len(ha.healthHistory[componentName]) > 100 {
		ha.healthHistory[componentName] = ha.healthHistory[componentName][len(ha.healthHistory[componentName])-100:]
	}

	// Update metrics
	ha.updateMetrics(status)
}

// updateMetrics updates health metrics for a component
func (ha *HealthAggregator) updateMetrics(status *HealthStatus) {
	componentName := status.ComponentName

	if _, exists := ha.metrics[componentName]; !exists {
		ha.metrics[componentName] = &HealthMetrics{
			ComponentName: componentName,
			HealthScore:   100.0,
		}
	}

	metrics := ha.metrics[componentName]
	metrics.TotalChecks++

	// Update failure/recovery counts
	if status.Status == HealthStateUnhealthy || status.Status == HealthStateCritical {
		metrics.FailureCount++
		metrics.ConsecutiveFailures++
		now := time.Now()
		metrics.LastFailureTime = &now
		
		// Decrease health score
		metrics.HealthScore = max(0, metrics.HealthScore-5.0)
	} else {
		if metrics.ConsecutiveFailures > 0 {
			metrics.RecoveryCount++
			now := time.Now()
			metrics.LastRecoveryTime = &now
		}
		metrics.ConsecutiveFailures = 0
		
		// Increase health score
		metrics.HealthScore = min(100.0, metrics.HealthScore+1.0)
	}

	// Calculate uptime percentage
	if metrics.TotalChecks > 0 {
		successfulChecks := metrics.TotalChecks - metrics.FailureCount
		metrics.UptimePercentage = float64(successfulChecks) / float64(metrics.TotalChecks) * 100.0
	}

	// Update response time metrics (simplified)
	if metrics.MeanResponseTime == 0 {
		metrics.MeanResponseTime = status.ResponseTime
	} else {
		// Simple moving average
		metrics.MeanResponseTime = (metrics.MeanResponseTime + status.ResponseTime) / 2
	}
}

// removeComponent removes a component from the aggregator
func (ha *HealthAggregator) removeComponent(componentName string) {
	ha.mu.Lock()
	defer ha.mu.Unlock()

	delete(ha.healthHistory, componentName)
	delete(ha.metrics, componentName)
}

// AlertManager methods

// triggerAlert triggers an alert for a component
func (am *AlertManager) triggerAlert(status *HealthStatus) {
	if !am.config.Enabled {
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	componentName := status.ComponentName

	// Check cooldown
	if lastAlert, exists := am.lastAlertTime[componentName]; exists {
		if time.Since(lastAlert) < am.config.Cooldown {
			return
		}
	}

	// Create alert
	alert := &Alert{
		ID:            fmt.Sprintf("%s-%d", componentName, time.Now().Unix()),
		ComponentName: componentName,
		Severity:      mapHealthStateToSeverity(status.Status),
		State:         status.Status,
		Message:       status.Message,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	am.activeAlerts[componentName] = alert
	am.alertHistory = append(am.alertHistory, alert)
	am.lastAlertTime[componentName] = time.Now()
}

// resolveAlert resolves an alert for a component
func (am *AlertManager) resolveAlert(componentName string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if alert, exists := am.activeAlerts[componentName]; exists {
		now := time.Now()
		alert.ResolvedAt = &now
		alert.UpdatedAt = now
		delete(am.activeAlerts, componentName)
	}
}

// processAlerts processes active alerts
func (am *AlertManager) processAlerts(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Process escalations and send notifications
			am.processEscalations()
		case <-ctx.Done():
			return
		}
	}
}

// processEscalations processes alert escalations
func (am *AlertManager) processEscalations() {
	am.mu.RLock()
	defer am.mu.RUnlock()

	for _, alert := range am.activeAlerts {
		// Simple escalation logic - would be more complex in real implementation
		if time.Since(alert.CreatedAt) > 5*time.Minute && alert.Escalations == 0 {
			alert.Escalations++
			alert.UpdatedAt = time.Now()
		}
	}
}

// Helper functions

func mapHealthStateToSeverity(state HealthState) Severity {
	switch state {
	case HealthStateCritical:
		return SeverityCritical
	case HealthStateUnhealthy:
		return SeverityHigh
	case HealthStateDegraded:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}