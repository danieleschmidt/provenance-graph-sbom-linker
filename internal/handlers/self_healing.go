package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/pipeline"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/autoscaling"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
)

// SelfHealingHandler provides endpoints for self-healing system monitoring
type SelfHealingHandler struct {
	selfHealingPipeline *pipeline.SelfHealingPipeline
	anomalyDetector     *pipeline.AnomalyDetector
	intelligentScaler   *autoscaling.IntelligentScaler
	metricsCollector    *monitoring.MetricsCollector
}

// NewSelfHealingHandler creates a new self-healing handler
func NewSelfHealingHandler(
	selfHealingPipeline *pipeline.SelfHealingPipeline,
	anomalyDetector *pipeline.AnomalyDetector,
	intelligentScaler *autoscaling.IntelligentScaler,
	metricsCollector *monitoring.MetricsCollector,
) *SelfHealingHandler {
	return &SelfHealingHandler{
		selfHealingPipeline: selfHealingPipeline,
		anomalyDetector:     anomalyDetector,
		intelligentScaler:   intelligentScaler,
		metricsCollector:    metricsCollector,
	}
}

// GetOverallHealth returns the overall health status of the self-healing system
func (shh *SelfHealingHandler) GetOverallHealth(c *gin.Context) {
	overallHealth := shh.selfHealingPipeline.GetOverallHealth()
	componentHealth := shh.selfHealingPipeline.GetComponentHealth()
	currentWorkers := shh.intelligentScaler.GetCurrentWorkers()
	recentAnomalies := shh.anomalyDetector.GetAnomalies(10)
	recentScaling := shh.intelligentScaler.GetScalingHistory(5)
	
	health := map[string]interface{}{
		"overall_status":      overallHealth.String(),
		"component_health":    componentHealth,
		"current_workers":     currentWorkers,
		"recent_anomalies":    len(recentAnomalies),
		"recent_scaling":      len(recentScaling),
		"timestamp":           time.Now(),
		"self_healing_active": true,
	}
	
	statusCode := http.StatusOK
	if overallHealth == pipeline.HealthStatusCritical {
		statusCode = http.StatusServiceUnavailable
	} else if overallHealth == pipeline.HealthStatusUnhealthy {
		statusCode = http.StatusPartialContent
	}
	
	c.JSON(statusCode, health)
}

// GetComponentHealth returns detailed health information for all components
func (shh *SelfHealingHandler) GetComponentHealth(c *gin.Context) {
	componentHealth := shh.selfHealingPipeline.GetComponentHealth()
	circuitBreakerStatus := shh.selfHealingPipeline.GetCircuitBreakerStatus()
	
	detailedHealth := make(map[string]interface{})
	for componentID, health := range componentHealth {
		detailedHealth[componentID] = map[string]interface{}{
			"status":                 health.Status.String(),
			"last_health_check":      health.LastHealthCheck,
			"consecutive_failures":   health.ConsecutiveFailures,
			"consecutive_successes":  health.ConsecutiveSuccesses,
			"error_rate":             health.ErrorRate,
			"latency_ms":             health.Latency.Milliseconds(),
			"throughput":             health.Throughput,
			"resource_usage":         health.ResourceUsage,
			"last_error":             health.LastError,
			"circuit_breaker_state": circuitBreakerStatus[componentID].String(),
		}
	}
	
	c.JSON(http.StatusOK, gin.H{
		"components": detailedHealth,
		"timestamp": time.Now(),
	})
}

// GetHealingActions returns the history of healing actions taken by the system
func (shh *SelfHealingHandler) GetHealingActions(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 50
	}
	
	healingActions := shh.selfHealingPipeline.GetHealingActions(limit)
	
	c.JSON(http.StatusOK, gin.H{
		"healing_actions": healingActions,
		"total_actions":   len(healingActions),
		"timestamp":       time.Now(),
	})
}

// GetAnomalies returns detected anomalies
func (shh *SelfHealingHandler) GetAnomalies(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 50
	}
	
	metricName := c.Query("metric")
	
	var anomalies []pipeline.Anomaly
	if metricName != "" {
		anomalies = shh.anomalyDetector.GetAnomaliesByMetric(metricName, limit)
	} else {
		anomalies = shh.anomalyDetector.GetAnomalies(limit)
	}
	
	stats := shh.anomalyDetector.GetAnomalyStats()
	
	c.JSON(http.StatusOK, gin.H{
		"anomalies":  anomalies,
		"statistics": stats,
		"timestamp":  time.Now(),
	})
}

// GetBaselines returns current baseline models used for anomaly detection
func (shh *SelfHealingHandler) GetBaselines(c *gin.Context) {
	baselines := shh.anomalyDetector.GetBaselines()
	
	c.JSON(http.StatusOK, gin.H{
		"baselines": baselines,
		"timestamp": time.Now(),
	})
}

// ResolveAnomaly marks an anomaly as resolved
func (shh *SelfHealingHandler) ResolveAnomaly(c *gin.Context) {
	anomalyID := c.Param("id")
	if anomalyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "anomaly ID is required"})
		return
	}
	
	err := shh.anomalyDetector.ResolveAnomaly(anomalyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message":   "Anomaly resolved successfully",
		"anomaly_id": anomalyID,
		"timestamp": time.Now(),
	})
}

// GetScalingStatus returns current auto-scaling status and metrics
func (shh *SelfHealingHandler) GetScalingStatus(c *gin.Context) {
	scalingMetrics := shh.intelligentScaler.GetScalingMetrics()
	prediction := shh.intelligentScaler.GetPrediction()
	
	c.JSON(http.StatusOK, gin.H{
		"scaling_metrics": scalingMetrics,
		"prediction":      prediction,
		"timestamp":       time.Now(),
	})
}

// GetScalingHistory returns the history of scaling events
func (shh *SelfHealingHandler) GetScalingHistory(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 50
	}
	
	scalingHistory := shh.intelligentScaler.GetScalingHistory(limit)
	
	c.JSON(http.StatusOK, gin.H{
		"scaling_history": scalingHistory,
		"total_events":    len(scalingHistory),
		"timestamp":       time.Now(),
	})
}

// ManualScale allows manual scaling of the system
func (shh *SelfHealingHandler) ManualScale(c *gin.Context) {
	var request struct {
		TargetWorkers int    `json:"target_workers" binding:"required,min=1,max=100"`
		Reason        string `json:"reason" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	err := shh.intelligentScaler.ManualScale(request.TargetWorkers, request.Reason)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message":        "Manual scaling initiated",
		"target_workers": request.TargetWorkers,
		"reason":         request.Reason,
		"timestamp":      time.Now(),
	})
}

// ReportComponentFailure allows manual reporting of component failures
func (shh *SelfHealingHandler) ReportComponentFailure(c *gin.Context) {
	var request struct {
		ComponentID string `json:"component_id" binding:"required"`
		ErrorMsg    string `json:"error_message" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	shh.selfHealingPipeline.ReportComponentFailure(request.ComponentID, request.ErrorMsg)
	
	c.JSON(http.StatusOK, gin.H{
		"message":      "Component failure reported",
		"component_id": request.ComponentID,
		"timestamp":    time.Now(),
	})
}

// ReportComponentSuccess allows manual reporting of component successes
func (shh *SelfHealingHandler) ReportComponentSuccess(c *gin.Context) {
	var request struct {
		ComponentID string `json:"component_id" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	shh.selfHealingPipeline.ReportComponentSuccess(request.ComponentID)
	
	c.JSON(http.StatusOK, gin.H{
		"message":      "Component success reported",
		"component_id": request.ComponentID,
		"timestamp":    time.Now(),
	})
}

// GetHealthDashboard returns comprehensive health dashboard data
func (shh *SelfHealingHandler) GetHealthDashboard(c *gin.Context) {
	// Collect comprehensive dashboard data
	overallHealth := shh.selfHealingPipeline.GetOverallHealth()
	componentHealth := shh.selfHealingPipeline.GetComponentHealth()
	healingActions := shh.selfHealingPipeline.GetHealingActions(10)
	anomalies := shh.anomalyDetector.GetAnomalies(10)
	anomalyStats := shh.anomalyDetector.GetAnomalyStats()
	scalingHistory := shh.intelligentScaler.GetScalingHistory(10)
	scalingMetrics := shh.intelligentScaler.GetScalingMetrics()
	appMetrics := shh.metricsCollector.GetApplicationMetrics()
	
	// Calculate health scores
	healthScores := make(map[string]float64)
	for componentID, health := range componentHealth {
		switch health.Status {
		case pipeline.HealthStatusHealthy:
			healthScores[componentID] = 1.0
		case pipeline.HealthStatusDegraded:
			healthScores[componentID] = 0.7
		case pipeline.HealthStatusUnhealthy:
			healthScores[componentID] = 0.4
		case pipeline.HealthStatusCritical:
			healthScores[componentID] = 0.1
		default:
			healthScores[componentID] = 0.5
		}
	}
	
	// Create dashboard response
	dashboard := gin.H{
		"overview": gin.H{
			"overall_health":       overallHealth.String(),
			"health_scores":        healthScores,
			"total_components":     len(componentHealth),
			"healthy_components":   countHealthyComponents(componentHealth),
			"current_workers":      shh.intelligentScaler.GetCurrentWorkers(),
			"active_anomalies":     countActiveAnomalies(anomalies),
			"recent_healing_actions": len(healingActions),
		},
		"component_health": componentHealth,
		"recent_events": gin.H{
			"healing_actions": healingActions,
			"anomalies":       anomalies,
			"scaling_events":  scalingHistory,
		},
		"metrics": gin.H{
			"application": appMetrics,
			"scaling":     scalingMetrics,
			"anomaly_stats": anomalyStats,
		},
		"timestamp": time.Now(),
	}
	
	c.JSON(http.StatusOK, dashboard)
}

// Helper functions

func countHealthyComponents(componentHealth map[string]pipeline.ComponentHealth) int {
	count := 0
	for _, health := range componentHealth {
		if health.Status == pipeline.HealthStatusHealthy {
			count++
		}
	}
	return count
}

func countActiveAnomalies(anomalies []pipeline.Anomaly) int {
	count := 0
	for _, anomaly := range anomalies {
		if !anomaly.Resolved {
			count++
		}
	}
	return count
}
