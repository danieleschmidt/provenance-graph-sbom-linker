package autoscaling

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
	"github.com/sirupsen/logrus"
)

// IntelligentScaler implements machine learning-based auto-scaling
type IntelligentScaler struct {
	config           ScalingConfig
	metricsCollector *monitoring.MetricsCollector
	predictor        *LoadPredictor
	scalingHistory   []ScalingEvent
	currentWorkers   int
	lastScaleTime    time.Time
	logger           *logrus.Logger
	mutex            sync.RWMutex
	running          bool
	stopCh           chan struct{}
}

// ScalingConfig defines configuration for intelligent scaling
type ScalingConfig struct {
	Enabled                 bool          `json:"enabled"`
	MinWorkers              int           `json:"min_workers"`
	MaxWorkers              int           `json:"max_workers"`
	TargetCPUUtilization    float64       `json:"target_cpu_utilization"`
	TargetMemoryUtilization float64       `json:"target_memory_utilization"`
	TargetQueueLength       int           `json:"target_queue_length"`
	CooldownPeriod          time.Duration `json:"cooldown_period"`
	ScaleUpThreshold        float64       `json:"scale_up_threshold"`
	ScaleDownThreshold      float64       `json:"scale_down_threshold"`
	PredictionWindow        time.Duration `json:"prediction_window"`
	PredictiveScaling       bool          `json:"predictive_scaling"`
	AggressiveScaling       bool          `json:"aggressive_scaling"`
	EvaluationInterval      time.Duration `json:"evaluation_interval"`
	SeasonalAdjustment      bool          `json:"seasonal_adjustment"`
	LoadBalanceAware        bool          `json:"load_balance_aware"`
	CostOptimization        bool          `json:"cost_optimization"`
}

// DefaultScalingConfig returns sensible defaults for scaling
func DefaultScalingConfig() ScalingConfig {
	return ScalingConfig{
		Enabled:                 true,
		MinWorkers:              2,
		MaxWorkers:              20,
		TargetCPUUtilization:    70.0,
		TargetMemoryUtilization: 80.0,
		TargetQueueLength:       10,
		CooldownPeriod:          2 * time.Minute,
		ScaleUpThreshold:        80.0,
		ScaleDownThreshold:      30.0,
		PredictionWindow:        10 * time.Minute,
		PredictiveScaling:       true,
		AggressiveScaling:       false,
		EvaluationInterval:      30 * time.Second,
		SeasonalAdjustment:      true,
		LoadBalanceAware:        true,
		CostOptimization:        true,
	}
}

// ScalingEvent represents a scaling decision and its outcome
type ScalingEvent struct {
	Timestamp      time.Time              `json:"timestamp"`
	Direction      ScalingDirection       `json:"direction"`
	FromWorkers    int                    `json:"from_workers"`
	ToWorkers      int                    `json:"to_workers"`
	Reason         string                 `json:"reason"`
	Trigger        ScalingTrigger         `json:"trigger"`
	Metrics        ScalingMetrics         `json:"metrics"`
	Predicted      bool                   `json:"predicted"`
	Success        bool                   `json:"success"`
	Duration       time.Duration          `json:"duration"`
	CostImpact     float64                `json:"cost_impact"`
	Effectiveness  float64                `json:"effectiveness"`
	Context        map[string]interface{} `json:"context"`
}

// ScalingDirection represents the direction of scaling
type ScalingDirection string

const (
	ScalingDirectionUp   ScalingDirection = "up"
	ScalingDirectionDown ScalingDirection = "down"
	ScalingDirectionNone ScalingDirection = "none"
)

// ScalingTrigger represents what triggered the scaling decision
type ScalingTrigger string

const (
	ScalingTriggerCPU        ScalingTrigger = "cpu"
	ScalingTriggerMemory     ScalingTrigger = "memory"
	ScalingTriggerQueue      ScalingTrigger = "queue"
	ScalingTriggerPrediction ScalingTrigger = "prediction"
	ScalingTriggerSeasonal   ScalingTrigger = "seasonal"
	ScalingTriggerManual     ScalingTrigger = "manual"
	ScalingTriggerComposite  ScalingTrigger = "composite"
)

// ScalingMetrics captures the metrics at the time of scaling decision
type ScalingMetrics struct {
	CPUUtilization    float64 `json:"cpu_utilization"`
	MemoryUtilization float64 `json:"memory_utilization"`
	QueueLength       int     `json:"queue_length"`
	Throughput        float64 `json:"throughput"`
	Latency           float64 `json:"latency"`
	ErrorRate         float64 `json:"error_rate"`
	ActiveConnections int     `json:"active_connections"`
	WorkerUtilization float64 `json:"worker_utilization"`
}

// LoadPredictor implements time series forecasting for predictive scaling
type LoadPredictor struct {
	historical    []MetricPoint
	seasonalData  map[int][]float64 // hour -> historical values
	trendData     []float64
	lastPrediction PredictionResult
	mutex         sync.RWMutex
}

// MetricPoint represents a point-in-time metric measurement
type MetricPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// PredictionResult contains the result of load prediction
type PredictionResult struct {
	PredictedValue    float64                `json:"predicted_value"`
	Confidence        float64                `json:"confidence"`
	Trend             float64                `json:"trend"`
	SeasonalFactor    float64                `json:"seasonal_factor"`
	PredictionWindow  time.Duration          `json:"prediction_window"`
	Timestamp         time.Time              `json:"timestamp"`
	Method            string                 `json:"method"`
	Context           map[string]interface{} `json:"context"`
}

// NewIntelligentScaler creates a new intelligent auto-scaler
func NewIntelligentScaler(
	config ScalingConfig,
	metricsCollector *monitoring.MetricsCollector,
	initialWorkers int,
	logger *logrus.Logger,
) *IntelligentScaler {
	return &IntelligentScaler{
		config:           config,
		metricsCollector: metricsCollector,
		predictor:        NewLoadPredictor(),
		scalingHistory:   make([]ScalingEvent, 0),
		currentWorkers:   initialWorkers,
		lastScaleTime:    time.Now(),
		logger:           logger,
		stopCh:           make(chan struct{}),
	}
}

// NewLoadPredictor creates a new load predictor
func NewLoadPredictor() *LoadPredictor {
	return &LoadPredictor{
		historical:   make([]MetricPoint, 0, 1000),
		seasonalData: make(map[int][]float64),
		trendData:    make([]float64, 0, 100),
	}
}

// Start starts the intelligent auto-scaler
func (is *IntelligentScaler) Start(ctx context.Context) error {
	if !is.config.Enabled {
		return nil
	}
	
	is.mutex.Lock()
	if is.running {
		is.mutex.Unlock()
		return fmt.Errorf("intelligent scaler is already running")
	}
	is.running = true
	is.mutex.Unlock()
	
	is.logger.Info("Starting intelligent auto-scaler")
	
	// Start evaluation loop
	go is.evaluationLoop(ctx)
	
	// Start prediction update loop
	if is.config.PredictiveScaling {
		go is.predictionLoop(ctx)
	}
	
	return nil
}

// Stop stops the intelligent auto-scaler
func (is *IntelligentScaler) Stop() error {
	is.mutex.Lock()
	defer is.mutex.Unlock()
	
	if !is.running {
		return nil
	}
	
	is.running = false
	close(is.stopCh)
	
	is.logger.Info("Stopped intelligent auto-scaler")
	return nil
}

// evaluationLoop runs the main scaling evaluation loop
func (is *IntelligentScaler) evaluationLoop(ctx context.Context) {
	ticker := time.NewTicker(is.config.EvaluationInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			is.evaluateScaling()
		case <-is.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// predictionLoop updates predictions periodically
func (is *IntelligentScaler) predictionLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute) // Update predictions every minute
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			is.updatePredictions()
		case <-is.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// evaluateScaling evaluates whether scaling is needed
func (is *IntelligentScaler) evaluateScaling() {
	// Check cooldown period
	if time.Since(is.lastScaleTime) < is.config.CooldownPeriod {
		return
	}
	
	// Collect current metrics
	metrics := is.collectCurrentMetrics()
	
	// Add to predictor
	is.predictor.AddDataPoint(MetricPoint{
		Timestamp: time.Now(),
		Value:     metrics.CPUUtilization,
		Metadata: map[string]interface{}{
			"memory_util": metrics.MemoryUtilization,
			"queue_length": metrics.QueueLength,
			"throughput": metrics.Throughput,
		},
	})
	
	// Determine scaling decision
	decision := is.makeScalingDecision(metrics)
	
	// Execute scaling if needed
	if decision.Direction != ScalingDirectionNone {
		is.executeScaling(decision, metrics)
	}
}

// collectCurrentMetrics collects current system metrics
func (is *IntelligentScaler) collectCurrentMetrics() ScalingMetrics {
	appMetrics := is.metricsCollector.GetApplicationMetrics()
	
	return ScalingMetrics{
		CPUUtilization:    appMetrics.CPUUsagePercent,
		MemoryUtilization: (appMetrics.MemoryUsageMB / 1024) * 100, // Convert to percentage (rough)
		QueueLength:       int(appMetrics.ActiveConnections),       // Use as proxy
		Throughput:        appMetrics.RequestsPerSecond,
		Latency:           appMetrics.ResponseTimeMs,
		ErrorRate:         appMetrics.ErrorRate,
		ActiveConnections: int(appMetrics.ActiveConnections),
		WorkerUtilization: appMetrics.WorkerPoolUtilization,
	}
}

// makeScalingDecision determines what scaling action to take
func (is *IntelligentScaler) makeScalingDecision(metrics ScalingMetrics) ScalingDecision {
	decision := ScalingDecision{
		Direction: ScalingDirectionNone,
		Trigger:   ScalingTriggerComposite,
		Reason:    "No scaling needed",
		Confidence: 0.0,
	}
	
	// Check for immediate scale-up conditions
	if is.shouldScaleUp(metrics) {
		decision.Direction = ScalingDirectionUp
		decision.Reason = is.getScaleUpReason(metrics)
		decision.Trigger = is.getScaleUpTrigger(metrics)
		decision.Confidence = is.calculateScaleUpConfidence(metrics)
		decision.TargetWorkers = is.calculateTargetWorkers(metrics, ScalingDirectionUp)
	} else if is.shouldScaleDown(metrics) {
		decision.Direction = ScalingDirectionDown
		decision.Reason = is.getScaleDownReason(metrics)
		decision.Trigger = is.getScaleDownTrigger(metrics)
		decision.Confidence = is.calculateScaleDownConfidence(metrics)
		decision.TargetWorkers = is.calculateTargetWorkers(metrics, ScalingDirectionDown)
	}
	
	// Consider predictive scaling
	if is.config.PredictiveScaling && decision.Direction == ScalingDirectionNone {
		predictiveDecision := is.makePredictiveScalingDecision(metrics)
		if predictiveDecision.Direction != ScalingDirectionNone {
			return predictiveDecision
		}
	}
	
	// Apply seasonal adjustments
	if is.config.SeasonalAdjustment {
		decision = is.applySeasonalAdjustment(decision, metrics)
	}
	
	return decision
}

// ScalingDecision represents a scaling decision
type ScalingDecision struct {
	Direction     ScalingDirection `json:"direction"`
	TargetWorkers int              `json:"target_workers"`
	Reason        string           `json:"reason"`
	Trigger       ScalingTrigger   `json:"trigger"`
	Confidence    float64          `json:"confidence"`
	Predicted     bool             `json:"predicted"`
	Urgency       ScalingUrgency   `json:"urgency"`
}

// ScalingUrgency represents how urgent the scaling action is
type ScalingUrgency string

const (
	ScalingUrgencyLow      ScalingUrgency = "low"
	ScalingUrgencyMedium   ScalingUrgency = "medium"
	ScalingUrgencyHigh     ScalingUrgency = "high"
	ScalingUrgencyCritical ScalingUrgency = "critical"
)

// shouldScaleUp determines if we should scale up
func (is *IntelligentScaler) shouldScaleUp(metrics ScalingMetrics) bool {
	if is.currentWorkers >= is.config.MaxWorkers {
		return false
	}
	
	// CPU-based scaling
	if metrics.CPUUtilization > is.config.ScaleUpThreshold {
		return true
	}
	
	// Memory-based scaling
	if metrics.MemoryUtilization > is.config.TargetMemoryUtilization {
		return true
	}
	
	// Queue-based scaling
	if metrics.QueueLength > is.config.TargetQueueLength*2 {
		return true
	}
	
	// Worker utilization
	if metrics.WorkerUtilization > 90.0 {
		return true
	}
	
	// Composite conditions for aggressive scaling
	if is.config.AggressiveScaling {
		if metrics.CPUUtilization > 60 && metrics.QueueLength > is.config.TargetQueueLength {
			return true
		}
	}
	
	return false
}

// shouldScaleDown determines if we should scale down
func (is *IntelligentScaler) shouldScaleDown(metrics ScalingMetrics) bool {
	if is.currentWorkers <= is.config.MinWorkers {
		return false
	}
	
	// Only scale down if all metrics are low
	if metrics.CPUUtilization < is.config.ScaleDownThreshold &&
	   metrics.MemoryUtilization < is.config.ScaleDownThreshold &&
	   metrics.QueueLength < is.config.TargetQueueLength/2 &&
	   metrics.WorkerUtilization < 50.0 {
		return true
	}
	
	return false
}

// getScaleUpReason returns the reason for scaling up
func (is *IntelligentScaler) getScaleUpReason(metrics ScalingMetrics) string {
	reasons := make([]string, 0)
	
	if metrics.CPUUtilization > is.config.ScaleUpThreshold {
		reasons = append(reasons, fmt.Sprintf("CPU utilization %.1f%% > %.1f%%", metrics.CPUUtilization, is.config.ScaleUpThreshold))
	}
	if metrics.MemoryUtilization > is.config.TargetMemoryUtilization {
		reasons = append(reasons, fmt.Sprintf("Memory utilization %.1f%% > %.1f%%", metrics.MemoryUtilization, is.config.TargetMemoryUtilization))
	}
	if metrics.QueueLength > is.config.TargetQueueLength*2 {
		reasons = append(reasons, fmt.Sprintf("Queue length %d > %d", metrics.QueueLength, is.config.TargetQueueLength*2))
	}
	if metrics.WorkerUtilization > 90.0 {
		reasons = append(reasons, fmt.Sprintf("Worker utilization %.1f%% > 90%%", metrics.WorkerUtilization))
	}
	
	if len(reasons) == 0 {
		return "Composite scaling conditions met"
	}
	
	return fmt.Sprintf("Scale up needed: %v", reasons)
}

// getScaleDownReason returns the reason for scaling down
func (is *IntelligentScaler) getScaleDownReason(metrics ScalingMetrics) string {
	return fmt.Sprintf("Low resource utilization: CPU %.1f%%, Memory %.1f%%, Queue %d, Workers %.1f%%",
		metrics.CPUUtilization, metrics.MemoryUtilization, metrics.QueueLength, metrics.WorkerUtilization)
}

// getScaleUpTrigger determines the primary trigger for scaling up
func (is *IntelligentScaler) getScaleUpTrigger(metrics ScalingMetrics) ScalingTrigger {
	if metrics.CPUUtilization > is.config.ScaleUpThreshold {
		return ScalingTriggerCPU
	}
	if metrics.MemoryUtilization > is.config.TargetMemoryUtilization {
		return ScalingTriggerMemory
	}
	if metrics.QueueLength > is.config.TargetQueueLength*2 {
		return ScalingTriggerQueue
	}
	return ScalingTriggerComposite
}

// getScaleDownTrigger determines the trigger for scaling down
func (is *IntelligentScaler) getScaleDownTrigger(metrics ScalingMetrics) ScalingTrigger {
	return ScalingTriggerComposite // Scale down is always composite
}

// calculateScaleUpConfidence calculates confidence for scale up decision
func (is *IntelligentScaler) calculateScaleUpConfidence(metrics ScalingMetrics) float64 {
	confidence := 0.0
	
	// CPU contribution
	if metrics.CPUUtilization > is.config.ScaleUpThreshold {
		confidence += 0.3 * (metrics.CPUUtilization - is.config.ScaleUpThreshold) / (100 - is.config.ScaleUpThreshold)
	}
	
	// Memory contribution
	if metrics.MemoryUtilization > is.config.TargetMemoryUtilization {
		confidence += 0.2 * (metrics.MemoryUtilization - is.config.TargetMemoryUtilization) / (100 - is.config.TargetMemoryUtilization)
	}
	
	// Queue contribution
	if metrics.QueueLength > is.config.TargetQueueLength {
		queueFactor := float64(metrics.QueueLength) / float64(is.config.TargetQueueLength)
		confidence += 0.3 * math.Min(queueFactor-1, 1)
	}
	
	// Worker utilization contribution
	if metrics.WorkerUtilization > 80 {
		confidence += 0.2 * (metrics.WorkerUtilization - 80) / 20
	}
	
	return math.Min(confidence, 1.0)
}

// calculateScaleDownConfidence calculates confidence for scale down decision
func (is *IntelligentScaler) calculateScaleDownConfidence(metrics ScalingMetrics) float64 {
	// Scale down confidence based on how low the metrics are
	cpuFactor := (is.config.ScaleDownThreshold - metrics.CPUUtilization) / is.config.ScaleDownThreshold
	memoryFactor := (is.config.ScaleDownThreshold - metrics.MemoryUtilization) / is.config.ScaleDownThreshold
	queueFactor := 1.0
	if metrics.QueueLength < is.config.TargetQueueLength/2 {
		queueFactor = 1.0 - float64(metrics.QueueLength)/float64(is.config.TargetQueueLength/2)
	}
	
	// Only scale down if we're confident
	confidence := (cpuFactor + memoryFactor + queueFactor) / 3
	return math.Max(0, math.Min(confidence, 1.0))
}

// calculateTargetWorkers calculates the optimal number of workers
func (is *IntelligentScaler) calculateTargetWorkers(metrics ScalingMetrics, direction ScalingDirection) int {
	if direction == ScalingDirectionUp {
		// Calculate based on the most constraining resource
		cpuWorkers := int(math.Ceil(float64(is.currentWorkers) * metrics.CPUUtilization / is.config.TargetCPUUtilization))
		memoryWorkers := int(math.Ceil(float64(is.currentWorkers) * metrics.MemoryUtilization / is.config.TargetMemoryUtilization))
		queueWorkers := is.currentWorkers + (metrics.QueueLength / is.config.TargetQueueLength)
		
		target := is.currentWorkers
		if cpuWorkers > target {
			target = cpuWorkers
		}
		if memoryWorkers > target {
			target = memoryWorkers
		}
		if queueWorkers > target {
			target = queueWorkers
		}
		
		// Scale gradually unless aggressive scaling is enabled
		if !is.config.AggressiveScaling {
			maxIncrease := int(math.Ceil(float64(is.currentWorkers) * 0.5)) // Max 50% increase
			if target > is.currentWorkers+maxIncrease {
				target = is.currentWorkers + maxIncrease
			}
		}
		
		return int(math.Min(float64(target), float64(is.config.MaxWorkers)))
	} else {
		// Scale down more conservatively
		reduction := 1
		if is.config.CostOptimization {
			// More aggressive scale down for cost optimization
			reduction = int(math.Ceil(float64(is.currentWorkers) * 0.25)) // Up to 25% reduction
		}
		
		target := is.currentWorkers - reduction
		return int(math.Max(float64(target), float64(is.config.MinWorkers)))
	}
}

// makePredictiveScalingDecision makes scaling decisions based on predictions
func (is *IntelligentScaler) makePredictiveScalingDecision(currentMetrics ScalingMetrics) ScalingDecision {
	prediction := is.predictor.PredictLoad(is.config.PredictionWindow)
	
	if prediction.Confidence < 0.7 {
		// Not confident enough in prediction
		return ScalingDecision{Direction: ScalingDirectionNone}
	}
	
	// Predict future resource needs
	predictedCPU := currentMetrics.CPUUtilization * (prediction.PredictedValue / 100.0)
	
	decision := ScalingDecision{
		Direction:  ScalingDirectionNone,
		Predicted:  true,
		Trigger:    ScalingTriggerPrediction,
		Confidence: prediction.Confidence,
	}
	
	if predictedCPU > is.config.ScaleUpThreshold {
		decision.Direction = ScalingDirectionUp
		decision.Reason = fmt.Sprintf("Predicted CPU utilization %.1f%% in %v", predictedCPU, is.config.PredictionWindow)
		decision.TargetWorkers = is.calculatePredictiveTargetWorkers(prediction, currentMetrics)
	} else if predictedCPU < is.config.ScaleDownThreshold {
		decision.Direction = ScalingDirectionDown
		decision.Reason = fmt.Sprintf("Predicted low CPU utilization %.1f%% in %v", predictedCPU, is.config.PredictionWindow)
		decision.TargetWorkers = is.calculatePredictiveTargetWorkers(prediction, currentMetrics)
	}
	
	return decision
}

// calculatePredictiveTargetWorkers calculates target workers based on predictions
func (is *IntelligentScaler) calculatePredictiveTargetWorkers(prediction PredictionResult, currentMetrics ScalingMetrics) int {
	// Use prediction to estimate future worker needs
	loadMultiplier := prediction.PredictedValue / 100.0
	estimatedWorkers := int(math.Ceil(float64(is.currentWorkers) * loadMultiplier))
	
	// Apply bounds
	if estimatedWorkers > is.config.MaxWorkers {
		estimatedWorkers = is.config.MaxWorkers
	}
	if estimatedWorkers < is.config.MinWorkers {
		estimatedWorkers = is.config.MinWorkers
	}
	
	return estimatedWorkers
}

// applySeasonalAdjustment applies seasonal adjustments to scaling decisions
func (is *IntelligentScaler) applySeasonalAdjustment(decision ScalingDecision, metrics ScalingMetrics) ScalingDecision {
	hour := time.Now().Hour()
	
	// Define peak hours (this could be configurable)
	peakHours := map[int]bool{
		9: true, 10: true, 11: true, // Morning peak
		14: true, 15: true, 16: true, // Afternoon peak
	}
	
	if peakHours[hour] && decision.Direction == ScalingDirectionNone {
		// During peak hours, be more proactive about scaling up
		if metrics.CPUUtilization > is.config.TargetCPUUtilization {
			decision.Direction = ScalingDirectionUp
			decision.Trigger = ScalingTriggerSeasonal
			decision.Reason = fmt.Sprintf("Seasonal adjustment for peak hour %d", hour)
			decision.TargetWorkers = is.currentWorkers + 1
			decision.Confidence = 0.6
		}
	}
	
	return decision
}

// executeScaling executes the scaling decision
func (is *IntelligentScaler) executeScaling(decision ScalingDecision, metrics ScalingMetrics) {
	startTime := time.Now()
	
	is.logger.WithFields(logrus.Fields{
		"direction":      decision.Direction,
		"from_workers":   is.currentWorkers,
		"to_workers":     decision.TargetWorkers,
		"reason":         decision.Reason,
		"trigger":        decision.Trigger,
		"confidence":     decision.Confidence,
		"predicted":      decision.Predicted,
	}).Info("Executing scaling decision")
	
	// Create scaling event
	event := ScalingEvent{
		Timestamp:   startTime,
		Direction:   decision.Direction,
		FromWorkers: is.currentWorkers,
		ToWorkers:   decision.TargetWorkers,
		Reason:      decision.Reason,
		Trigger:     decision.Trigger,
		Metrics:     metrics,
		Predicted:   decision.Predicted,
		Context: map[string]interface{}{
			"confidence": decision.Confidence,
			"config":     is.config,
		},
	}
	
	// Simulate scaling execution (in real implementation, this would interact with the worker pool)
	success := is.performScaling(decision.TargetWorkers)
	
	event.Success = success
	event.Duration = time.Since(startTime)
	
	if success {
		is.currentWorkers = decision.TargetWorkers
		is.lastScaleTime = time.Now()
		
		// Calculate cost impact
		event.CostImpact = is.calculateCostImpact(event.FromWorkers, event.ToWorkers)
	}
	
	// Add to history
	is.addScalingEvent(event)
	
	// Update metrics collector
	if is.metricsCollector != nil {
		is.metricsCollector.SetCustomMetric("current_workers", is.currentWorkers)
	}
}

// performScaling simulates the actual scaling operation
func (is *IntelligentScaler) performScaling(targetWorkers int) bool {
	// In a real implementation, this would:
	// 1. Add/remove workers from the worker pool
	// 2. Update load balancer configuration
	// 3. Handle graceful shutdown of workers being removed
	// 4. Verify that new workers are healthy before marking success
	
	// For simulation, we'll just return success
	return true
}

// calculateCostImpact calculates the cost impact of scaling
func (is *IntelligentScaler) calculateCostImpact(fromWorkers, toWorkers int) float64 {
	// Simple cost model: $0.10 per worker per hour
	costPerWorkerPerHour := 0.10
	workerDifference := toWorkers - fromWorkers
	
	// Calculate hourly cost impact
	return float64(workerDifference) * costPerWorkerPerHour
}

// addScalingEvent adds a scaling event to history
func (is *IntelligentScaler) addScalingEvent(event ScalingEvent) {
	is.mutex.Lock()
	defer is.mutex.Unlock()
	
	is.scalingHistory = append(is.scalingHistory, event)
	
	// Keep only recent history (last 1000 events)
	if len(is.scalingHistory) > 1000 {
		is.scalingHistory = is.scalingHistory[100:] // Remove oldest 100
	}
}

// updatePredictions updates load predictions
func (is *IntelligentScaler) updatePredictions() {
	// This would collect recent metrics and update the prediction model
	currentMetrics := is.collectCurrentMetrics()
	
	is.predictor.AddDataPoint(MetricPoint{
		Timestamp: time.Now(),
		Value:     currentMetrics.CPUUtilization,
		Metadata: map[string]interface{}{
			"memory":     currentMetrics.MemoryUtilization,
			"queue":      currentMetrics.QueueLength,
			"throughput": currentMetrics.Throughput,
		},
	})
}

// LoadPredictor methods

// AddDataPoint adds a data point to the predictor
func (lp *LoadPredictor) AddDataPoint(point MetricPoint) {
	lp.mutex.Lock()
	defer lp.mutex.Unlock()
	
	lp.historical = append(lp.historical, point)
	
	// Keep only recent data (last 1000 points)
	if len(lp.historical) > 1000 {
		lp.historical = lp.historical[100:]
	}
	
	// Update seasonal data
	hour := point.Timestamp.Hour()
	if lp.seasonalData[hour] == nil {
		lp.seasonalData[hour] = make([]float64, 0)
	}
	lp.seasonalData[hour] = append(lp.seasonalData[hour], point.Value)
	
	// Keep only recent seasonal data per hour
	if len(lp.seasonalData[hour]) > 30 { // Keep 30 days of data per hour
		lp.seasonalData[hour] = lp.seasonalData[hour][1:]
	}
	
	// Update trend data
	lp.updateTrend()
}

// PredictLoad predicts future load for the given time window
func (lp *LoadPredictor) PredictLoad(window time.Duration) PredictionResult {
	lp.mutex.RLock()
	defer lp.mutex.RUnlock()
	
	if len(lp.historical) < 10 {
		// Not enough data for prediction
		return PredictionResult{
			PredictedValue:   50.0, // Default value
			Confidence:       0.1,
			PredictionWindow: window,
			Timestamp:        time.Now(),
			Method:           "default",
		}
	}
	
	// Get recent trend
	recentTrend := 0.0
	if len(lp.trendData) > 0 {
		recentTrend = lp.trendData[len(lp.trendData)-1]
	}
	
	// Get seasonal factor
	futureHour := time.Now().Add(window).Hour()
	seasonalFactor := lp.getSeasonalFactor(futureHour)
	
	// Simple prediction: current + trend + seasonal
	recentValue := lp.historical[len(lp.historical)-1].Value
	predictedValue := recentValue + recentTrend + seasonalFactor
	
	// Calculate confidence based on data consistency
	confidence := lp.calculatePredictionConfidence()
	
	lp.lastPrediction = PredictionResult{
		PredictedValue:   predictedValue,
		Confidence:       confidence,
		Trend:            recentTrend,
		SeasonalFactor:   seasonalFactor,
		PredictionWindow: window,
		Timestamp:        time.Now(),
		Method:           "trend_seasonal",
		Context: map[string]interface{}{
			"data_points":    len(lp.historical),
			"recent_value":   recentValue,
		},
	}
	
	return lp.lastPrediction
}

// updateTrend updates the trend calculation
func (lp *LoadPredictor) updateTrend() {
	if len(lp.historical) < 5 {
		return
	}
	
	// Calculate trend over last 10 points
	startIdx := len(lp.historical) - 10
	if startIdx < 0 {
		startIdx = 0
	}
	
	recentPoints := lp.historical[startIdx:]
	trend := lp.calculateLinearTrend(recentPoints)
	
	lp.trendData = append(lp.trendData, trend)
	if len(lp.trendData) > 100 {
		lp.trendData = lp.trendData[1:]
	}
}

// calculateLinearTrend calculates linear trend from data points
func (lp *LoadPredictor) calculateLinearTrend(points []MetricPoint) float64 {
	if len(points) < 2 {
		return 0
	}
	
	n := float64(len(points))
	sumX := 0.0
	sumY := 0.0
	sumXY := 0.0
	sumX2 := 0.0
	
	for i, point := range points {
		x := float64(i)
		y := point.Value
		
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}
	
	numerator := n*sumXY - sumX*sumY
	denominator := n*sumX2 - sumX*sumX
	
	if denominator == 0 {
		return 0
	}
	
	return numerator / denominator
}

// getSeasonalFactor gets the seasonal factor for a given hour
func (lp *LoadPredictor) getSeasonalFactor(hour int) float64 {
	if values, exists := lp.seasonalData[hour]; exists && len(values) > 0 {
		// Calculate average for this hour
		sum := 0.0
		for _, v := range values {
			sum += v
		}
		average := sum / float64(len(values))
		
		// Calculate overall average
		overallSum := 0.0
		overallCount := 0
		for _, hourValues := range lp.seasonalData {
			for _, v := range hourValues {
				overallSum += v
				overallCount++
			}
		}
		
		if overallCount > 0 {
			overallAverage := overallSum / float64(overallCount)
			return average - overallAverage
		}
	}
	
	return 0.0 // No seasonal adjustment
}

// calculatePredictionConfidence calculates confidence in predictions
func (lp *LoadPredictor) calculatePredictionConfidence() float64 {
	if len(lp.historical) < 10 {
		return 0.1
	}
	
	// Base confidence on data volume
	dataVolumeConfidence := math.Min(float64(len(lp.historical))/100.0, 1.0)
	
	// Calculate variance in recent data
	recentPoints := lp.historical
	if len(lp.historical) > 20 {
		recentPoints = lp.historical[len(lp.historical)-20:]
	}
	
	values := make([]float64, len(recentPoints))
	for i, point := range recentPoints {
		values[i] = point.Value
	}
	
	variance := lp.calculateVariance(values)
	varianceConfidence := 1.0 / (1.0 + variance/100.0) // Lower variance = higher confidence
	
	// Combine confidences
	totalConfidence := (dataVolumeConfidence + varianceConfidence) / 2.0
	return math.Max(0.1, math.Min(totalConfidence, 0.95))
}

// calculateVariance calculates variance of values
func (lp *LoadPredictor) calculateVariance(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	
	// Calculate mean
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	
	// Calculate variance
	sumSquaredDiff := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquaredDiff += diff * diff
	}
	
	return sumSquaredDiff / float64(len(values))
}

// Public API methods

// GetCurrentWorkers returns the current number of workers
func (is *IntelligentScaler) GetCurrentWorkers() int {
	is.mutex.RLock()
	defer is.mutex.RUnlock()
	return is.currentWorkers
}

// GetScalingHistory returns recent scaling events
func (is *IntelligentScaler) GetScalingHistory(limit int) []ScalingEvent {
	is.mutex.RLock()
	defer is.mutex.RUnlock()
	
	if limit <= 0 || limit > len(is.scalingHistory) {
		limit = len(is.scalingHistory)
	}
	
	start := len(is.scalingHistory) - limit
	if start < 0 {
		start = 0
	}
	
	result := make([]ScalingEvent, limit)
	copy(result, is.scalingHistory[start:])
	return result
}

// GetPrediction returns the latest load prediction
func (is *IntelligentScaler) GetPrediction() PredictionResult {
	return is.predictor.lastPrediction
}

// ManualScale manually scales to a specific number of workers
func (is *IntelligentScaler) ManualScale(targetWorkers int, reason string) error {
	if targetWorkers < is.config.MinWorkers || targetWorkers > is.config.MaxWorkers {
		return fmt.Errorf("target workers %d outside allowed range [%d, %d]", 
			targetWorkers, is.config.MinWorkers, is.config.MaxWorkers)
	}
	
	direction := ScalingDirectionNone
	if targetWorkers > is.currentWorkers {
		direction = ScalingDirectionUp
	} else if targetWorkers < is.currentWorkers {
		direction = ScalingDirectionDown
	}
	
	if direction == ScalingDirectionNone {
		return nil // Already at target
	}
	
	decision := ScalingDecision{
		Direction:     direction,
		TargetWorkers: targetWorkers,
		Reason:        reason,
		Trigger:       ScalingTriggerManual,
		Confidence:    1.0,
		Predicted:     false,
	}
	
	metrics := is.collectCurrentMetrics()
	is.executeScaling(decision, metrics)
	
	return nil
}

// GetScalingMetrics returns current scaling-related metrics
func (is *IntelligentScaler) GetScalingMetrics() map[string]interface{} {
	currentMetrics := is.collectCurrentMetrics()
	prediction := is.predictor.lastPrediction
	
	return map[string]interface{}{
		"current_workers":       is.currentWorkers,
		"min_workers":           is.config.MinWorkers,
		"max_workers":           is.config.MaxWorkers,
		"current_metrics":       currentMetrics,
		"last_prediction":       prediction,
		"last_scale_time":       is.lastScaleTime,
		"scaling_enabled":       is.config.Enabled,
		"predictive_enabled":    is.config.PredictiveScaling,
		"seasonal_enabled":      is.config.SeasonalAdjustment,
		"total_scaling_events":  len(is.scalingHistory),
	}
}
