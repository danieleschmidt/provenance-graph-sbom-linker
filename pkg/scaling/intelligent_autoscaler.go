package scaling

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// IntelligentAutoscaler provides ML-powered horizontal and vertical autoscaling
type IntelligentAutoscaler struct {
	name              string
	logger            *logrus.Logger
	config            *AutoscalerConfig
	predictor         *DemandPredictor
	scaler            *ResourceScaler
	optimizer         *CostOptimizer
	metrics           *ScalingMetrics
	mu               sync.RWMutex
	running          int32
	stopChan         chan struct{}
	scalingHistory   []*ScalingEvent
	currentResources *ResourceAllocation
	targetResources  *ResourceAllocation
}

// AutoscalerConfig configures the intelligent autoscaler
type AutoscalerConfig struct {
	// Basic scaling parameters
	MinInstances          int           `json:"min_instances"`
	MaxInstances          int           `json:"max_instances"`
	TargetCPUUtilization  float64       `json:"target_cpu_utilization"`
	TargetMemoryUtilization float64     `json:"target_memory_utilization"`
	ScaleUpCooldown       time.Duration `json:"scale_up_cooldown"`
	ScaleDownCooldown     time.Duration `json:"scale_down_cooldown"`
	
	// Advanced features
	PredictiveScalingEnabled     bool          `json:"predictive_scaling_enabled"`
	VerticalScalingEnabled       bool          `json:"vertical_scaling_enabled"`
	CostOptimizationEnabled      bool          `json:"cost_optimization_enabled"`
	MultiRegionScalingEnabled    bool          `json:"multi_region_scaling_enabled"`
	BurstCapacityEnabled         bool          `json:"burst_capacity_enabled"`
	
	// Prediction parameters
	PredictionHorizon            time.Duration `json:"prediction_horizon"`
	PredictionConfidenceThreshold float64      `json:"prediction_confidence_threshold"`
	SeasonalityDetectionEnabled   bool         `json:"seasonality_detection_enabled"`
	
	// Cost optimization
	MaxHourlyCost               float64       `json:"max_hourly_cost"`
	PreferredInstanceTypes      []string      `json:"preferred_instance_types"`
	SpotInstancesEnabled        bool          `json:"spot_instances_enabled"`
	CostVsPerformanceWeight     float64       `json:"cost_vs_performance_weight"`
	
	// Advanced scaling policies
	CustomScalingPolicies       []ScalingPolicy `json:"custom_scaling_policies"`
	TrafficPatternAnalysisEnabled bool         `json:"traffic_pattern_analysis_enabled"`
	LoadBalancerIntegration     bool          `json:"load_balancer_integration"`
	
	// Monitoring and alerting
	ScalingNotificationsEnabled bool          `json:"scaling_notifications_enabled"`
	MetricsRetentionDays       int           `json:"metrics_retention_days"`
	PerformanceLoggingEnabled  bool          `json:"performance_logging_enabled"`
}

// ScalingPolicy defines custom scaling rules
type ScalingPolicy struct {
	Name           string               `json:"name"`
	Conditions     []ScalingCondition   `json:"conditions"`
	Actions        []ScalingAction      `json:"actions"`
	Priority       int                  `json:"priority"`
	Enabled        bool                 `json:"enabled"`
	CooldownPeriod time.Duration        `json:"cooldown_period"`
}

// ScalingCondition defines when to trigger scaling
type ScalingCondition struct {
	Metric    string      `json:"metric"`
	Operator  string      `json:"operator"`
	Threshold float64     `json:"threshold"`
	Duration  time.Duration `json:"duration"`
}

// ScalingAction defines what action to take
type ScalingAction struct {
	Type       ScalingActionType `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
}

// ScalingActionType defines different types of scaling actions
type ScalingActionType string

const (
	ScalingActionScaleOut      ScalingActionType = "scale_out"
	ScalingActionScaleIn       ScalingActionType = "scale_in"
	ScalingActionScaleUp       ScalingActionType = "scale_up"
	ScalingActionScaleDown     ScalingActionType = "scale_down"
	ScalingActionPreWarm       ScalingActionType = "pre_warm"
	ScalingActionMigrate       ScalingActionType = "migrate"
	ScalingActionOptimize      ScalingActionType = "optimize"
)

// DemandPredictor predicts future resource demand using ML
type DemandPredictor struct {
	enabled              bool
	model               *PredictiveModel
	historicalData      []DataPoint
	trainingWindow      time.Duration
	predictionAccuracy  float64
	seasonalPatterns    map[string]*SeasonalPattern
	mu                 sync.RWMutex
}

// PredictiveModel contains the ML model for demand prediction
type PredictiveModel struct {
	ModelType       ModelType `json:"model_type"`
	Coefficients    []float64 `json:"coefficients"`
	Intercept       float64   `json:"intercept"`
	Seasonality     map[string]float64 `json:"seasonality"`
	TrendComponent  float64   `json:"trend_component"`
	Accuracy        float64   `json:"accuracy"`
	LastTrainedAt   time.Time `json:"last_trained_at"`
	Trained         bool      `json:"trained"`
}

// ModelType defines different prediction model types
type ModelType string

const (
	ModelTypeLinearRegression    ModelType = "linear_regression"
	ModelTypeARIMA              ModelType = "arima"
	ModelTypeNeuralNetwork      ModelType = "neural_network"
	ModelTypeEnsemble          ModelType = "ensemble"
)

// DataPoint represents a single data point for prediction
type DataPoint struct {
	Timestamp      time.Time `json:"timestamp"`
	CPUUtilization float64   `json:"cpu_utilization"`
	MemoryUtilization float64 `json:"memory_utilization"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	ResponseTime   float64   `json:"response_time"`
	ActiveConnections int64  `json:"active_connections"`
	QueueDepth     int64     `json:"queue_depth"`
	ExternalFactors map[string]float64 `json:"external_factors"`
}

// SeasonalPattern represents recurring patterns in demand
type SeasonalPattern struct {
	Pattern     []float64 `json:"pattern"`
	Confidence  float64   `json:"confidence"`
	Period      time.Duration `json:"period"`
	Amplitude   float64   `json:"amplitude"`
	Phase       float64   `json:"phase"`
}

// ResourceScaler handles actual scaling operations
type ResourceScaler struct {
	config          *ScalerConfig
	providers       map[string]CloudProvider
	currentState    *ResourceState
	pendingActions  []*ScalingAction
	mu             sync.RWMutex
}

// ScalerConfig configures the resource scaler
type ScalerConfig struct {
	DefaultProvider      string                 `json:"default_provider"`
	ProviderConfigs     map[string]interface{} `json:"provider_configs"`
	MaxConcurrentScaling int                    `json:"max_concurrent_scaling"`
	ScalingTimeoutSecs  int                    `json:"scaling_timeout_secs"`
}

// CloudProvider interface for different cloud providers
type CloudProvider interface {
	ScaleHorizontally(ctx context.Context, instances int) error
	ScaleVertically(ctx context.Context, resources ResourceSpec) error
	GetCurrentState(ctx context.Context) (*ResourceState, error)
	GetAvailableInstanceTypes() []InstanceType
	EstimateCost(resources ResourceSpec) float64
}

// ResourceState represents current resource allocation
type ResourceState struct {
	Instances       int                    `json:"instances"`
	InstanceType    string                 `json:"instance_type"`
	CPUCores        float64               `json:"cpu_cores"`
	MemoryGB        float64               `json:"memory_gb"`
	Region          string                `json:"region"`
	AvailabilityZones []string            `json:"availability_zones"`
	SpotInstances   int                   `json:"spot_instances"`
	ReservedInstances int                 `json:"reserved_instances"`
	LastUpdated     time.Time             `json:"last_updated"`
}

// ResourceSpec specifies desired resource configuration
type ResourceSpec struct {
	CPUCores     float64 `json:"cpu_cores"`
	MemoryGB     float64 `json:"memory_gb"`
	InstanceType string  `json:"instance_type"`
	SpotEnabled  bool    `json:"spot_enabled"`
}

// InstanceType represents available instance configurations
type InstanceType struct {
	Name         string  `json:"name"`
	CPUCores     float64 `json:"cpu_cores"`
	MemoryGB     float64 `json:"memory_gb"`
	NetworkGbps  float64 `json:"network_gbps"`
	StorageGB    int     `json:"storage_gb"`
	HourlyCost   float64 `json:"hourly_cost"`
	SpotCost     float64 `json:"spot_cost"`
	Optimized    []string `json:"optimized"`
}

// CostOptimizer optimizes resource allocation for cost efficiency
type CostOptimizer struct {
	config           *CostConfig
	pricingData      map[string]*PricingInfo
	reservations     []*Reservation
	costHistory      []*CostRecord
	optimizationRules []OptimizationRule
	mu              sync.RWMutex
}

// CostConfig configures cost optimization
type CostConfig struct {
	MaxHourlyCost        float64 `json:"max_hourly_cost"`
	CostEfficiencyTarget float64 `json:"cost_efficiency_target"`
	SpotInstanceRatio    float64 `json:"spot_instance_ratio"`
	ReservationStrategy  string  `json:"reservation_strategy"`
}

// PricingInfo contains pricing data for different resources
type PricingInfo struct {
	InstanceType    string    `json:"instance_type"`
	Region         string    `json:"region"`
	OnDemandPrice  float64   `json:"on_demand_price"`
	SpotPrice      float64   `json:"spot_price"`
	ReservedPrice  float64   `json:"reserved_price"`
	LastUpdated    time.Time `json:"last_updated"`
}

// ResourceAllocation represents current and target resource allocation
type ResourceAllocation struct {
	HorizontalScale *HorizontalScaleConfig `json:"horizontal_scale"`
	VerticalScale   *VerticalScaleConfig   `json:"vertical_scale"`
	TotalCost      float64                `json:"total_cost"`
	Efficiency     float64                `json:"efficiency"`
	LastUpdated    time.Time              `json:"last_updated"`
}

// HorizontalScaleConfig defines horizontal scaling configuration
type HorizontalScaleConfig struct {
	CurrentInstances int       `json:"current_instances"`
	TargetInstances  int       `json:"target_instances"`
	MaxInstances     int       `json:"max_instances"`
	MinInstances     int       `json:"min_instances"`
	ScaleDirection   string    `json:"scale_direction"`
	LastScaledAt     time.Time `json:"last_scaled_at"`
}

// VerticalScaleConfig defines vertical scaling configuration  
type VerticalScaleConfig struct {
	CurrentCPU    float64   `json:"current_cpu"`
	CurrentMemory float64   `json:"current_memory"`
	TargetCPU     float64   `json:"target_cpu"`
	TargetMemory  float64   `json:"target_memory"`
	LastScaledAt  time.Time `json:"last_scaled_at"`
}

// ScalingMetrics tracks autoscaling performance
type ScalingMetrics struct {
	TotalScalingEvents     int64              `json:"total_scaling_events"`
	SuccessfulScalings     int64              `json:"successful_scalings"`
	FailedScalings        int64              `json:"failed_scalings"`
	AverageScalingTime    time.Duration      `json:"average_scaling_time"`
	CostSavings           float64            `json:"cost_savings"`
	EfficiencyGains       float64            `json:"efficiency_gains"`
	PredictionAccuracy    float64            `json:"prediction_accuracy"`
	ResourceUtilization   *UtilizationMetrics `json:"resource_utilization"`
	ScalingsByType        map[ScalingActionType]int64 `json:"scalings_by_type"`
	LastUpdated          time.Time           `json:"last_updated"`
}

// UtilizationMetrics tracks resource utilization
type UtilizationMetrics struct {
	CPU        float64 `json:"cpu"`
	Memory     float64 `json:"memory"`
	Network    float64 `json:"network"`
	Storage    float64 `json:"storage"`
	Efficiency float64 `json:"efficiency"`
}

// ScalingEvent represents a scaling action that was taken
type ScalingEvent struct {
	ID               string            `json:"id"`
	Type             ScalingActionType `json:"type"`
	Timestamp        time.Time         `json:"timestamp"`
	Trigger          string            `json:"trigger"`
	BeforeState      *ResourceState    `json:"before_state"`
	AfterState       *ResourceState    `json:"after_state"`
	Duration         time.Duration     `json:"duration"`
	Success          bool              `json:"success"`
	ErrorMessage     string            `json:"error_message,omitempty"`
	CostImpact       float64           `json:"cost_impact"`
	PerformanceImpact float64          `json:"performance_impact"`
	PredictedBy      string            `json:"predicted_by,omitempty"`
}

// OptimizationRule defines cost optimization rules
type OptimizationRule struct {
	Name        string                 `json:"name"`
	Condition   func(*ResourceState) bool
	Action      func(ctx context.Context, state *ResourceState) (*ResourceState, error)
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Description string                 `json:"description"`
}

// CostRecord tracks historical cost data
type CostRecord struct {
	Timestamp    time.Time `json:"timestamp"`
	TotalCost    float64   `json:"total_cost"`
	InstanceCost float64   `json:"instance_cost"`
	StorageCost  float64   `json:"storage_cost"`
	NetworkCost  float64   `json:"network_cost"`
	Optimization string    `json:"optimization"`
}

// Reservation represents reserved instance allocations
type Reservation struct {
	ID           string        `json:"id"`
	InstanceType string        `json:"instance_type"`
	Count        int           `json:"count"`
	Region       string        `json:"region"`
	Duration     time.Duration `json:"duration"`
	ExpiresAt    time.Time     `json:"expires_at"`
	HourlyCost   float64       `json:"hourly_cost"`
	Utilization  float64       `json:"utilization"`
}

// NewIntelligentAutoscaler creates a new intelligent autoscaler
func NewIntelligentAutoscaler(name string, config *AutoscalerConfig, logger *logrus.Logger) *IntelligentAutoscaler {
	autoscaler := &IntelligentAutoscaler{
		name:           name,
		logger:         logger,
		config:         config,
		stopChan:       make(chan struct{}),
		scalingHistory: make([]*ScalingEvent, 0),
		metrics: &ScalingMetrics{
			ScalingsByType: make(map[ScalingActionType]int64),
			ResourceUtilization: &UtilizationMetrics{},
			LastUpdated: time.Now(),
		},
		currentResources: &ResourceAllocation{
			HorizontalScale: &HorizontalScaleConfig{
				CurrentInstances: config.MinInstances,
				TargetInstances:  config.MinInstances,
				MaxInstances:     config.MaxInstances,
				MinInstances:     config.MinInstances,
			},
			VerticalScale: &VerticalScaleConfig{},
			LastUpdated:   time.Now(),
		},
	}

	// Initialize demand predictor if enabled
	if config.PredictiveScalingEnabled {
		autoscaler.predictor = NewDemandPredictor(&PredictorConfig{
			Enabled:                      true,
			PredictionHorizon:           config.PredictionHorizon,
			ConfidenceThreshold:         config.PredictionConfidenceThreshold,
			SeasonalityDetectionEnabled: config.SeasonalityDetectionEnabled,
		})
	}

	// Initialize resource scaler
	autoscaler.scaler = NewResourceScaler(&ScalerConfig{
		DefaultProvider:      "aws",
		MaxConcurrentScaling: 3,
		ScalingTimeoutSecs:  300,
	})

	// Initialize cost optimizer if enabled
	if config.CostOptimizationEnabled {
		autoscaler.optimizer = NewCostOptimizer(&CostConfig{
			MaxHourlyCost:        config.MaxHourlyCost,
			CostEfficiencyTarget: 0.8,
			SpotInstanceRatio:    0.3,
			ReservationStrategy:  "balanced",
		})
	}

	logger.WithFields(logrus.Fields{
		"autoscaler": name,
		"config":     config,
	}).Info("Intelligent autoscaler initialized")

	return autoscaler
}

// NewDemandPredictor creates a new demand predictor
func NewDemandPredictor(config *PredictorConfig) *DemandPredictor {
	return &DemandPredictor{
		enabled:         config.Enabled,
		trainingWindow:  24 * time.Hour,
		historicalData:  make([]DataPoint, 0),
		seasonalPatterns: make(map[string]*SeasonalPattern),
		model: &PredictiveModel{
			ModelType: ModelTypeLinearRegression,
		},
	}
}

// PredictorConfig configures the demand predictor
type PredictorConfig struct {
	Enabled                      bool
	PredictionHorizon           time.Duration
	ConfidenceThreshold         float64
	SeasonalityDetectionEnabled bool
}

// NewResourceScaler creates a new resource scaler
func NewResourceScaler(config *ScalerConfig) *ResourceScaler {
	return &ResourceScaler{
		config:         config,
		providers:      make(map[string]CloudProvider),
		pendingActions: make([]*ScalingAction, 0),
		currentState: &ResourceState{
			Instances:    1,
			InstanceType: "m5.large",
			CPUCores:     2,
			MemoryGB:     8,
			Region:       "us-east-1",
			LastUpdated:  time.Now(),
		},
	}
}

// NewCostOptimizer creates a new cost optimizer
func NewCostOptimizer(config *CostConfig) *CostOptimizer {
	return &CostOptimizer{
		config:            config,
		pricingData:      make(map[string]*PricingInfo),
		reservations:     make([]*Reservation, 0),
		costHistory:      make([]*CostRecord, 0),
		optimizationRules: make([]OptimizationRule, 0),
	}
}

// Start starts the intelligent autoscaler
func (ia *IntelligentAutoscaler) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&ia.running, 0, 1) {
		return fmt.Errorf("autoscaler is already running")
	}

	ia.logger.Info("Starting intelligent autoscaler")

	// Start monitoring and scaling loop
	go ia.scalingLoop(ctx)

	// Start predictive analysis if enabled
	if ia.config.PredictiveScalingEnabled && ia.predictor != nil {
		go ia.predictiveAnalysisLoop(ctx)
	}

	// Start cost optimization if enabled
	if ia.config.CostOptimizationEnabled && ia.optimizer != nil {
		go ia.costOptimizationLoop(ctx)
	}

	// Start metrics collection
	go ia.metricsCollectionLoop(ctx)

	return nil
}

// Stop stops the intelligent autoscaler
func (ia *IntelligentAutoscaler) Stop() error {
	if !atomic.CompareAndSwapInt32(&ia.running, 1, 0) {
		return fmt.Errorf("autoscaler is not running")
	}

	close(ia.stopChan)
	ia.logger.Info("Stopped intelligent autoscaler")
	return nil
}

// scalingLoop is the main scaling decision loop
func (ia *IntelligentAutoscaler) scalingLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ia.evaluateScalingDecisions(ctx)
		case <-ctx.Done():
			return
		case <-ia.stopChan:
			return
		}
	}
}

// evaluateScalingDecisions evaluates whether scaling is needed
func (ia *IntelligentAutoscaler) evaluateScalingDecisions(ctx context.Context) {
	// Get current metrics
	currentMetrics := ia.getCurrentMetrics(ctx)
	
	// Check if scaling is needed based on current load
	scalingDecision := ia.analyzeScalingNeed(currentMetrics)
	
	// Apply predictive insights if enabled
	if ia.config.PredictiveScalingEnabled && ia.predictor != nil {
		predictiveDecision := ia.predictor.getPredictiveScalingDecision(ctx)
		scalingDecision = ia.combinePredictiveAndReactiveDecisions(scalingDecision, predictiveDecision)
	}
	
	// Apply cost optimization if enabled
	if ia.config.CostOptimizationEnabled && ia.optimizer != nil {
		scalingDecision = ia.optimizer.optimizeScalingDecision(scalingDecision)
	}
	
	// Execute scaling action if needed
	if scalingDecision.Action != "" {
		ia.executeScalingAction(ctx, scalingDecision)
	}
}

// getCurrentMetrics gets current system metrics
func (ia *IntelligentAutoscaler) getCurrentMetrics(ctx context.Context) *SystemMetrics {
	// Simulate getting real metrics - in real implementation would query monitoring system
	return &SystemMetrics{
		CPUUtilization:    75.0,
		MemoryUtilization: 68.0,
		RequestsPerSecond: 1250.0,
		ResponseTime:      85.0,
		ActiveConnections: 450,
		QueueDepth:        12,
		Timestamp:         time.Now(),
	}
}

// SystemMetrics represents current system metrics
type SystemMetrics struct {
	CPUUtilization     float64   `json:"cpu_utilization"`
	MemoryUtilization  float64   `json:"memory_utilization"`
	RequestsPerSecond  float64   `json:"requests_per_second"`
	ResponseTime       float64   `json:"response_time"`
	ActiveConnections  int64     `json:"active_connections"`
	QueueDepth         int64     `json:"queue_depth"`
	ErrorRate          float64   `json:"error_rate"`
	NetworkUtilization float64   `json:"network_utilization"`
	Timestamp          time.Time `json:"timestamp"`
}

// ScalingDecision represents a scaling decision
type ScalingDecision struct {
	Action         ScalingActionType      `json:"action"`
	TargetValue    interface{}            `json:"target_value"`
	Confidence     float64                `json:"confidence"`
	Reason         string                 `json:"reason"`
	CostImpact     float64                `json:"cost_impact"`
	ExpectedBenefit float64               `json:"expected_benefit"`
	Urgency        string                 `json:"urgency"`
	Parameters     map[string]interface{} `json:"parameters"`
}

// analyzeScalingNeed analyzes current metrics to determine scaling needs
func (ia *IntelligentAutoscaler) analyzeScalingNeed(metrics *SystemMetrics) *ScalingDecision {
	decision := &ScalingDecision{
		Confidence: 0.0,
		Parameters: make(map[string]interface{}),
	}

	// Check CPU utilization
	if metrics.CPUUtilization > ia.config.TargetCPUUtilization {
		scaleFactor := metrics.CPUUtilization / ia.config.TargetCPUUtilization
		decision.Action = ScalingActionScaleOut
		decision.TargetValue = int(math.Ceil(float64(ia.currentResources.HorizontalScale.CurrentInstances) * scaleFactor))
		decision.Confidence = min(0.9, scaleFactor-1.0)
		decision.Reason = fmt.Sprintf("CPU utilization %.1f%% exceeds target %.1f%%", metrics.CPUUtilization, ia.config.TargetCPUUtilization)
		decision.Urgency = "medium"
		
		if metrics.CPUUtilization > 90.0 {
			decision.Urgency = "high"
			decision.Confidence = 0.95
		}
	} else if metrics.CPUUtilization < ia.config.TargetCPUUtilization*0.5 && 
			   ia.currentResources.HorizontalScale.CurrentInstances > ia.config.MinInstances {
		decision.Action = ScalingActionScaleIn
		decision.TargetValue = max(ia.config.MinInstances, 
			int(math.Floor(float64(ia.currentResources.HorizontalScale.CurrentInstances) * 
				metrics.CPUUtilization / ia.config.TargetCPUUtilization)))
		decision.Confidence = 0.7
		decision.Reason = fmt.Sprintf("CPU utilization %.1f%% well below target, scale in possible", metrics.CPUUtilization)
		decision.Urgency = "low"
	}

	// Check memory utilization
	if metrics.MemoryUtilization > ia.config.TargetMemoryUtilization && decision.Action == "" {
		decision.Action = ScalingActionScaleOut
		decision.Reason = fmt.Sprintf("Memory utilization %.1f%% exceeds target %.1f%%", metrics.MemoryUtilization, ia.config.TargetMemoryUtilization)
		decision.Confidence = 0.8
	}

	return decision
}

// executeScalingAction executes a scaling decision
func (ia *IntelligentAutoscaler) executeScalingAction(ctx context.Context, decision *ScalingDecision) {
	startTime := time.Now()
	
	event := &ScalingEvent{
		ID:        fmt.Sprintf("scale-%d", time.Now().Unix()),
		Type:      decision.Action,
		Timestamp: startTime,
		Trigger:   decision.Reason,
		BeforeState: &ResourceState{
			Instances: ia.currentResources.HorizontalScale.CurrentInstances,
		},
	}

	ia.logger.WithFields(logrus.Fields{
		"action":     decision.Action,
		"reason":     decision.Reason,
		"confidence": decision.Confidence,
		"urgency":    decision.Urgency,
	}).Info("Executing scaling action")

	var err error
	switch decision.Action {
	case ScalingActionScaleOut, ScalingActionScaleIn:
		err = ia.executeHorizontalScaling(ctx, decision)
	case ScalingActionScaleUp, ScalingActionScaleDown:
		err = ia.executeVerticalScaling(ctx, decision)
	case ScalingActionPreWarm:
		err = ia.executePreWarming(ctx, decision)
	}

	// Record scaling event
	event.Duration = time.Since(startTime)
	event.Success = (err == nil)
	if err != nil {
		event.ErrorMessage = err.Error()
		ia.logger.WithError(err).Error("Scaling action failed")
	}

	event.AfterState = &ResourceState{
		Instances: ia.currentResources.HorizontalScale.TargetInstances,
	}

	ia.recordScalingEvent(event)
}

// executeHorizontalScaling executes horizontal scaling
func (ia *IntelligentAutoscaler) executeHorizontalScaling(ctx context.Context, decision *ScalingDecision) error {
	targetInstances := decision.TargetValue.(int)
	
	// Validate scaling limits
	if targetInstances > ia.config.MaxInstances {
		targetInstances = ia.config.MaxInstances
	}
	if targetInstances < ia.config.MinInstances {
		targetInstances = ia.config.MinInstances
	}

	// Check cooldown periods
	if !ia.canScaleNow(decision.Action) {
		return fmt.Errorf("scaling action blocked by cooldown period")
	}

	// Update target
	ia.mu.Lock()
	ia.currentResources.HorizontalScale.TargetInstances = targetInstances
	ia.currentResources.HorizontalScale.LastScaledAt = time.Now()
	ia.mu.Unlock()

	// Simulate scaling operation
	time.Sleep(100 * time.Millisecond)

	// Update current instances (simulated)
	ia.mu.Lock()
	ia.currentResources.HorizontalScale.CurrentInstances = targetInstances
	ia.mu.Unlock()

	// Update metrics
	atomic.AddInt64(&ia.metrics.TotalScalingEvents, 1)
	atomic.AddInt64(&ia.metrics.SuccessfulScalings, 1)
	ia.metrics.ScalingsByType[decision.Action]++

	ia.logger.WithFields(logrus.Fields{
		"target_instances": targetInstances,
		"action":          decision.Action,
	}).Info("Horizontal scaling completed")

	return nil
}

// executeVerticalScaling executes vertical scaling
func (ia *IntelligentAutoscaler) executeVerticalScaling(ctx context.Context, decision *ScalingDecision) error {
	if !ia.config.VerticalScalingEnabled {
		return fmt.Errorf("vertical scaling is not enabled")
	}

	// Simulate vertical scaling
	time.Sleep(200 * time.Millisecond)

	ia.logger.WithField("action", decision.Action).Info("Vertical scaling completed")
	return nil
}

// executePreWarming executes resource pre-warming
func (ia *IntelligentAutoscaler) executePreWarming(ctx context.Context, decision *ScalingDecision) error {
	// Simulate pre-warming operation
	time.Sleep(50 * time.Millisecond)

	ia.logger.Info("Resource pre-warming completed")
	return nil
}

// canScaleNow checks if scaling can be performed based on cooldown periods
func (ia *IntelligentAutoscaler) canScaleNow(action ScalingActionType) bool {
	ia.mu.RLock()
	lastScaled := ia.currentResources.HorizontalScale.LastScaledAt
	ia.mu.RUnlock()

	var cooldown time.Duration
	switch action {
	case ScalingActionScaleOut, ScalingActionScaleUp:
		cooldown = ia.config.ScaleUpCooldown
	case ScalingActionScaleIn, ScalingActionScaleDown:
		cooldown = ia.config.ScaleDownCooldown
	default:
		return true
	}

	return time.Since(lastScaled) >= cooldown
}

// recordScalingEvent records a scaling event
func (ia *IntelligentAutoscaler) recordScalingEvent(event *ScalingEvent) {
	ia.mu.Lock()
	defer ia.mu.Unlock()

	ia.scalingHistory = append(ia.scalingHistory, event)

	// Keep only recent history (last 100 events)
	if len(ia.scalingHistory) > 100 {
		ia.scalingHistory = ia.scalingHistory[len(ia.scalingHistory)-100:]
	}
}

// predictiveAnalysisLoop runs predictive analysis
func (ia *IntelligentAutoscaler) predictiveAnalysisLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ia.predictor.analyzePatterns(ctx)
		case <-ctx.Done():
			return
		case <-ia.stopChan:
			return
		}
	}
}

// costOptimizationLoop runs cost optimization
func (ia *IntelligentAutoscaler) costOptimizationLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ia.optimizer.optimizeResourceAllocation(ctx)
		case <-ctx.Done():
			return
		case <-ia.stopChan:
			return
		}
	}
}

// metricsCollectionLoop collects and updates metrics
func (ia *IntelligentAutoscaler) metricsCollectionLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ia.updateMetrics(ctx)
		case <-ctx.Done():
			return
		case <-ia.stopChan:
			return
		}
	}
}

// updateMetrics updates autoscaler metrics
func (ia *IntelligentAutoscaler) updateMetrics(ctx context.Context) {
	currentMetrics := ia.getCurrentMetrics(ctx)
	
	ia.mu.Lock()
	defer ia.mu.Unlock()

	// Update resource utilization metrics
	ia.metrics.ResourceUtilization.CPU = currentMetrics.CPUUtilization
	ia.metrics.ResourceUtilization.Memory = currentMetrics.MemoryUtilization
	ia.metrics.ResourceUtilization.Network = currentMetrics.NetworkUtilization
	
	// Calculate efficiency
	utilizationSum := currentMetrics.CPUUtilization + currentMetrics.MemoryUtilization
	ia.metrics.ResourceUtilization.Efficiency = utilizationSum / 200.0 // Average of CPU and Memory

	ia.metrics.LastUpdated = time.Now()
}

// Public API methods

// GetCurrentState returns current autoscaler state
func (ia *IntelligentAutoscaler) GetCurrentState() *ResourceAllocation {
	ia.mu.RLock()
	defer ia.mu.RUnlock()

	// Return a copy
	return &ResourceAllocation{
		HorizontalScale: &HorizontalScaleConfig{
			CurrentInstances: ia.currentResources.HorizontalScale.CurrentInstances,
			TargetInstances:  ia.currentResources.HorizontalScale.TargetInstances,
			MaxInstances:     ia.currentResources.HorizontalScale.MaxInstances,
			MinInstances:     ia.currentResources.HorizontalScale.MinInstances,
			LastScaledAt:     ia.currentResources.HorizontalScale.LastScaledAt,
		},
		VerticalScale: &VerticalScaleConfig{
			CurrentCPU:    ia.currentResources.VerticalScale.CurrentCPU,
			CurrentMemory: ia.currentResources.VerticalScale.CurrentMemory,
			TargetCPU:     ia.currentResources.VerticalScale.TargetCPU,
			TargetMemory:  ia.currentResources.VerticalScale.TargetMemory,
			LastScaledAt:  ia.currentResources.VerticalScale.LastScaledAt,
		},
		TotalCost:   ia.currentResources.TotalCost,
		Efficiency:  ia.currentResources.Efficiency,
		LastUpdated: ia.currentResources.LastUpdated,
	}
}

// GetMetrics returns current autoscaler metrics
func (ia *IntelligentAutoscaler) GetMetrics() *ScalingMetrics {
	ia.mu.RLock()
	defer ia.mu.RUnlock()

	// Return a copy
	metricsCopy := *ia.metrics
	metricsCopy.ScalingsByType = make(map[ScalingActionType]int64)
	for k, v := range ia.metrics.ScalingsByType {
		metricsCopy.ScalingsByType[k] = v
	}

	return &metricsCopy
}

// GetScalingHistory returns recent scaling events
func (ia *IntelligentAutoscaler) GetScalingHistory() []*ScalingEvent {
	ia.mu.RLock()
	defer ia.mu.RUnlock()

	// Return a copy of the slice
	history := make([]*ScalingEvent, len(ia.scalingHistory))
	copy(history, ia.scalingHistory)
	return history
}

// ForceScale forces a scaling action (for testing/emergency)
func (ia *IntelligentAutoscaler) ForceScale(ctx context.Context, action ScalingActionType, targetValue interface{}) error {
	decision := &ScalingDecision{
		Action:      action,
		TargetValue: targetValue,
		Confidence:  1.0,
		Reason:      "forced_scaling",
		Urgency:     "high",
	}

	return ia.executeScalingAction(ctx, decision)
}

// Predictor methods

// getPredictiveScalingDecision gets a predictive scaling decision
func (dp *DemandPredictor) getPredictiveScalingDecision(ctx context.Context) *ScalingDecision {
	if !dp.enabled || !dp.model.Trained {
		return &ScalingDecision{Confidence: 0.0}
	}

	// Simulate predictive decision
	return &ScalingDecision{
		Action:      ScalingActionPreWarm,
		Confidence:  0.8,
		Reason:      "predictive_demand_increase",
		Urgency:     "medium",
	}
}

// analyzePatterns analyzes historical patterns
func (dp *DemandPredictor) analyzePatterns(ctx context.Context) {
	// Simulate pattern analysis
	dp.mu.Lock()
	defer dp.mu.Unlock()

	if len(dp.historicalData) > 50 {
		dp.model.Trained = true
		dp.predictionAccuracy = 0.85
	}
}

// Optimizer methods

// optimizeScalingDecision applies cost optimization to scaling decision
func (co *CostOptimizer) optimizeScalingDecision(decision *ScalingDecision) *ScalingDecision {
	// Apply cost-aware modifications to the scaling decision
	if decision.Action == ScalingActionScaleOut {
		// Check if cost limit would be exceeded
		estimatedCost := co.estimateScalingCost(decision)
		if estimatedCost > co.config.MaxHourlyCost {
			// Reduce scaling or suggest spot instances
			decision.Parameters["use_spot_instances"] = true
		}
	}

	return decision
}

// optimizeResourceAllocation optimizes overall resource allocation
func (co *CostOptimizer) optimizeResourceAllocation(ctx context.Context) {
	// Simulate cost optimization
	co.mu.Lock()
	defer co.mu.Unlock()

	// Analyze current costs and suggest optimizations
}

// estimateScalingCost estimates the cost impact of scaling
func (co *CostOptimizer) estimateScalingCost(decision *ScalingDecision) float64 {
	// Simulate cost calculation
	return 10.0 // $10/hour estimated increase
}

// Helper functions

// combinePredictiveAndReactiveDecisions combines two scaling decisions
func (ia *IntelligentAutoscaler) combinePredictiveAndReactiveDecisions(reactive, predictive *ScalingDecision) *ScalingDecision {
	// If reactive decision has high confidence, use it
	if reactive.Confidence > 0.8 {
		return reactive
	}

	// If predictive decision suggests pre-warming, consider it
	if predictive.Action == ScalingActionPreWarm && predictive.Confidence > 0.7 {
		return predictive
	}

	// Default to reactive decision
	return reactive
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}