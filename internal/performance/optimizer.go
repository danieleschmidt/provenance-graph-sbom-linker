package performance

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// OptimizationStrategy defines different optimization approaches
type OptimizationStrategy string

const (
	StrategyThroughput OptimizationStrategy = "throughput"
	StrategyLatency    OptimizationStrategy = "latency"
	StrategyMemory     OptimizationStrategy = "memory"
	StrategyBalance    OptimizationStrategy = "balance"
)

// PerformanceMetric represents a performance measurement
type PerformanceMetric struct {
	Name      string                 `json:"name"`
	Value     float64                `json:"value"`
	Unit      string                 `json:"unit"`
	Timestamp time.Time              `json:"timestamp"`
	Labels    map[string]string      `json:"labels,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// OptimizationTarget defines what to optimize
type OptimizationTarget struct {
	Component   string            `json:"component"`
	Metric      string            `json:"metric"`
	Target      float64           `json:"target"`
	Tolerance   float64           `json:"tolerance"`
	Priority    int               `json:"priority"` // 1-10, higher is more important
	Constraints map[string]float64 `json:"constraints,omitempty"`
}

// OptimizationAction represents an optimization action
type OptimizationAction struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Component   string                 `json:"component"`
	Parameters  map[string]interface{} `json:"parameters"`
	Impact      OptimizationImpact     `json:"impact"`
	Duration    time.Duration          `json:"duration"`
	Reversible  bool                   `json:"reversible"`
	RiskLevel   float64                `json:"risk_level"` // 0.0-1.0
}

// OptimizationImpact describes the expected impact of an action
type OptimizationImpact struct {
	CPU         float64 `json:"cpu_change"`         // % change in CPU usage
	Memory      float64 `json:"memory_change"`      // % change in memory usage
	Throughput  float64 `json:"throughput_change"`  // % change in throughput
	Latency     float64 `json:"latency_change"`     // % change in latency
	Confidence  float64 `json:"confidence"`         // 0.0-1.0
}

// PerformanceOptimizer provides intelligent performance optimization
type PerformanceOptimizer struct {
	strategy      OptimizationStrategy
	targets       []OptimizationTarget
	metrics       map[string][]PerformanceMetric
	actions       map[string]OptimizationAction
	activeActions map[string]bool
	mutex         sync.RWMutex
	logger        *logrus.Logger
	
	// Performance tracking
	metricsWindow time.Duration
	sampleRate    time.Duration
	running       bool
	ctx           context.Context
	cancel        context.CancelFunc
	
	// Optimization state
	lastOptimization time.Time
	optimizationCooldown time.Duration
	maxConcurrentActions int
	
	// Statistics
	stats OptimizationStats
}

// OptimizationStats tracks optimization performance
type OptimizationStats struct {
	TotalOptimizations    int64     `json:"total_optimizations"`
	SuccessfulActions     int64     `json:"successful_actions"`
	FailedActions         int64     `json:"failed_actions"`
	TotalImprovementPct   float64   `json:"total_improvement_percent"`
	LastOptimization      time.Time `json:"last_optimization"`
	AverageOptimizationTime time.Duration `json:"average_optimization_time"`
}

// OptimizerConfig configures the performance optimizer
type OptimizerConfig struct {
	Strategy                OptimizationStrategy
	MetricsWindow          time.Duration
	SampleRate             time.Duration
	OptimizationCooldown   time.Duration
	MaxConcurrentActions   int
	RiskThreshold          float64
}

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer(config OptimizerConfig, logger *logrus.Logger) *PerformanceOptimizer {
	if logger == nil {
		logger = logrus.New()
	}
	
	return &PerformanceOptimizer{
		strategy:                config.Strategy,
		targets:                 make([]OptimizationTarget, 0),
		metrics:                 make(map[string][]PerformanceMetric),
		actions:                 make(map[string]OptimizationAction),
		activeActions:          make(map[string]bool),
		logger:                 logger,
		metricsWindow:          config.MetricsWindow,
		sampleRate:             config.SampleRate,
		optimizationCooldown:   config.OptimizationCooldown,
		maxConcurrentActions:   config.MaxConcurrentActions,
	}
}

// Start begins the optimization process
func (po *PerformanceOptimizer) Start(ctx context.Context) error {
	po.mutex.Lock()
	if po.running {
		po.mutex.Unlock()
		return fmt.Errorf("optimizer is already running")
	}
	
	po.ctx, po.cancel = context.WithCancel(ctx)
	po.running = true
	po.mutex.Unlock()
	
	// Register built-in optimization actions
	po.registerBuiltInActions()
	
	// Start metrics collection
	go po.collectMetrics()
	
	// Start optimization loop
	go po.optimizationLoop()
	
	po.logger.WithField("strategy", po.strategy).Info("Performance optimizer started")
	return nil
}

// Stop stops the optimization process
func (po *PerformanceOptimizer) Stop() {
	po.mutex.Lock()
	defer po.mutex.Unlock()
	
	if !po.running {
		return
	}
	
	po.cancel()
	po.running = false
	
	po.logger.Info("Performance optimizer stopped")
}

// AddTarget adds an optimization target
func (po *PerformanceOptimizer) AddTarget(target OptimizationTarget) {
	po.mutex.Lock()
	defer po.mutex.Unlock()
	
	po.targets = append(po.targets, target)
	
	// Sort targets by priority (highest first)
	sort.Slice(po.targets, func(i, j int) bool {
		return po.targets[i].Priority > po.targets[j].Priority
	})
	
	po.logger.WithFields(logrus.Fields{
		"component": target.Component,
		"metric":    target.Metric,
		"target":    target.Target,
		"priority":  target.Priority,
	}).Info("Added optimization target")
}

// RecordMetric records a performance metric
func (po *PerformanceOptimizer) RecordMetric(metric PerformanceMetric) {
	po.mutex.Lock()
	defer po.mutex.Unlock()
	
	key := fmt.Sprintf("%s.%s", metric.Labels["component"], metric.Name)
	if po.metrics[key] == nil {
		po.metrics[key] = make([]PerformanceMetric, 0)
	}
	
	po.metrics[key] = append(po.metrics[key], metric)
	
	// Keep only recent metrics within the window
	cutoff := time.Now().Add(-po.metricsWindow)
	var filtered []PerformanceMetric
	for _, m := range po.metrics[key] {
		if m.Timestamp.After(cutoff) {
			filtered = append(filtered, m)
		}
	}
	po.metrics[key] = filtered
}

// GetMetrics returns current metrics
func (po *PerformanceOptimizer) GetMetrics() map[string][]PerformanceMetric {
	po.mutex.RLock()
	defer po.mutex.RUnlock()
	
	result := make(map[string][]PerformanceMetric)
	for key, metrics := range po.metrics {
		result[key] = append([]PerformanceMetric{}, metrics...)
	}
	
	return result
}

// GetOptimizationSuggestions returns optimization suggestions
func (po *PerformanceOptimizer) GetOptimizationSuggestions() []OptimizationAction {
	po.mutex.RLock()
	defer po.mutex.RUnlock()
	
	var suggestions []OptimizationAction
	
	for _, target := range po.targets {
		current := po.getCurrentMetricValue(target.Component, target.Metric)
		if current == -1 {
			continue // No data available
		}
		
		// Check if target is not met
		difference := target.Target - current
		if difference > target.Tolerance {
			actions := po.getActionsForTarget(target, difference)
			suggestions = append(suggestions, actions...)
		}
	}
	
	// Sort by impact and risk
	sort.Slice(suggestions, func(i, j int) bool {
		impactI := po.calculateActionScore(suggestions[i])
		impactJ := po.calculateActionScore(suggestions[j])
		return impactI > impactJ
	})
	
	return suggestions
}

// ApplyOptimization applies a specific optimization action
func (po *PerformanceOptimizer) ApplyOptimization(actionID string) error {
	po.mutex.Lock()
	defer po.mutex.Unlock()
	
	action, exists := po.actions[actionID]
	if !exists {
		return fmt.Errorf("optimization action %s not found", actionID)
	}
	
	if po.activeActions[actionID] {
		return fmt.Errorf("optimization action %s is already active", actionID)
	}
	
	// Check concurrent action limit
	activeCount := len(po.activeActions)
	if activeCount >= po.maxConcurrentActions {
		return fmt.Errorf("maximum concurrent actions (%d) reached", po.maxConcurrentActions)
	}
	
	// Apply the action
	start := time.Now()
	err := po.executeAction(action)
	duration := time.Since(start)
	
	if err != nil {
		atomic.AddInt64(&po.stats.FailedActions, 1)
		po.logger.WithError(err).WithField("action_id", actionID).Error("Failed to apply optimization action")
		return err
	}
	
	po.activeActions[actionID] = true
	atomic.AddInt64(&po.stats.SuccessfulActions, 1)
	atomic.AddInt64(&po.stats.TotalOptimizations, 1)
	
	po.logger.WithFields(logrus.Fields{
		"action_id":  actionID,
		"component":  action.Component,
		"type":       action.Type,
		"duration":   duration,
	}).Info("Applied optimization action")
	
	return nil
}

// GetOptimizationStats returns optimization statistics
func (po *PerformanceOptimizer) GetOptimizationStats() OptimizationStats {
	return OptimizationStats{
		TotalOptimizations:    atomic.LoadInt64(&po.stats.TotalOptimizations),
		SuccessfulActions:     atomic.LoadInt64(&po.stats.SuccessfulActions),
		FailedActions:         atomic.LoadInt64(&po.stats.FailedActions),
		TotalImprovementPct:   po.stats.TotalImprovementPct,
		LastOptimization:      po.stats.LastOptimization,
		AverageOptimizationTime: po.stats.AverageOptimizationTime,
	}
}

// Internal methods
func (po *PerformanceOptimizer) collectMetrics() {
	ticker := time.NewTicker(po.sampleRate)
	defer ticker.Stop()
	
	for {
		select {
		case <-po.ctx.Done():
			return
		case <-ticker.C:
			po.collectSystemMetrics()
		}
	}
}

func (po *PerformanceOptimizer) collectSystemMetrics() {
	now := time.Now()
	
	// Collect Go runtime metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	metrics := []PerformanceMetric{
		{
			Name:      "cpu_usage",
			Value:     po.getCPUUsage(),
			Unit:      "percent",
			Timestamp: now,
			Labels:    map[string]string{"component": "system"},
		},
		{
			Name:      "memory_usage",
			Value:     float64(memStats.Alloc),
			Unit:      "bytes",
			Timestamp: now,
			Labels:    map[string]string{"component": "system"},
		},
		{
			Name:      "goroutines",
			Value:     float64(runtime.NumGoroutine()),
			Unit:      "count",
			Timestamp: now,
			Labels:    map[string]string{"component": "runtime"},
		},
		{
			Name:      "gc_pause",
			Value:     float64(memStats.PauseTotalNs) / 1e6, // Convert to ms
			Unit:      "milliseconds",
			Timestamp: now,
			Labels:    map[string]string{"component": "gc"},
		},
	}
	
	for _, metric := range metrics {
		po.RecordMetric(metric)
	}
}

func (po *PerformanceOptimizer) getCPUUsage() float64 {
	// Simplified CPU usage calculation
	// In production, this would use more sophisticated methods
	runtime.GC()
	return float64(runtime.NumGoroutine()) / 100.0 // Rough approximation
}

func (po *PerformanceOptimizer) optimizationLoop() {
	ticker := time.NewTicker(time.Minute) // Check for optimizations every minute
	defer ticker.Stop()
	
	for {
		select {
		case <-po.ctx.Done():
			return
		case <-ticker.C:
			if time.Since(po.lastOptimization) >= po.optimizationCooldown {
				po.performOptimization()
			}
		}
	}
}

func (po *PerformanceOptimizer) performOptimization() {
	suggestions := po.GetOptimizationSuggestions()
	if len(suggestions) == 0 {
		return
	}
	
	// Apply the top suggestion if it's safe
	topSuggestion := suggestions[0]
	if topSuggestion.RiskLevel <= 0.3 { // Only apply low-risk optimizations automatically
		if err := po.ApplyOptimization(topSuggestion.ID); err != nil {
			po.logger.WithError(err).Warn("Failed to apply automatic optimization")
		} else {
			po.lastOptimization = time.Now()
		}
	}
}

func (po *PerformanceOptimizer) getCurrentMetricValue(component, metric string) float64 {
	key := fmt.Sprintf("%s.%s", component, metric)
	metrics := po.metrics[key]
	
	if len(metrics) == 0 {
		return -1
	}
	
	// Return the most recent value
	return metrics[len(metrics)-1].Value
}

func (po *PerformanceOptimizer) getActionsForTarget(target OptimizationTarget, gap float64) []OptimizationAction {
	var actions []OptimizationAction
	
	// Generate actions based on the target
	switch target.Metric {
	case "cpu_usage":
		if gap > 0 { // Need to reduce CPU usage
			actions = append(actions, po.actions["reduce_goroutines"])
			actions = append(actions, po.actions["optimize_gc"])
		}
	case "memory_usage":
		if gap > 0 { // Need to reduce memory usage
			actions = append(actions, po.actions["trigger_gc"])
			actions = append(actions, po.actions["reduce_allocations"])
		}
	case "throughput":
		if gap < 0 { // Need to increase throughput
			actions = append(actions, po.actions["increase_workers"])
			actions = append(actions, po.actions["optimize_batch_size"])
		}
	}
	
	return actions
}

func (po *PerformanceOptimizer) calculateActionScore(action OptimizationAction) float64 {
	// Score = Impact / Risk
	impact := action.Impact.CPU + action.Impact.Memory + action.Impact.Throughput - action.Impact.Latency
	risk := action.RiskLevel
	
	if risk == 0 {
		risk = 0.1 // Avoid division by zero
	}
	
	return (impact * action.Impact.Confidence) / risk
}

func (po *PerformanceOptimizer) executeAction(action OptimizationAction) error {
	// This is where specific optimization actions would be implemented
	// For now, we'll just simulate the execution
	
	po.logger.WithFields(logrus.Fields{
		"action_type": action.Type,
		"component":   action.Component,
		"parameters":  action.Parameters,
	}).Info("Executing optimization action")
	
	// Simulate execution time
	time.Sleep(action.Duration)
	
	return nil
}

func (po *PerformanceOptimizer) registerBuiltInActions() {
	actions := map[string]OptimizationAction{
		"reduce_goroutines": {
			ID:        "reduce_goroutines",
			Type:      "scale_down",
			Component: "runtime",
			Parameters: map[string]interface{}{
				"target_reduction": 0.2,
			},
			Impact: OptimizationImpact{
				CPU:        -15.0,
				Memory:     -10.0,
				Throughput: -5.0,
				Latency:    5.0,
				Confidence: 0.8,
			},
			Duration:   time.Second * 5,
			Reversible: true,
			RiskLevel:  0.2,
		},
		"optimize_gc": {
			ID:        "optimize_gc",
			Type:      "gc_tune",
			Component: "gc",
			Parameters: map[string]interface{}{
				"target_percent": 50,
			},
			Impact: OptimizationImpact{
				CPU:        -10.0,
				Memory:     5.0,
				Throughput: 8.0,
				Latency:    -12.0,
				Confidence: 0.85,
			},
			Duration:   time.Second * 2,
			Reversible: true,
			RiskLevel:  0.15,
		},
		"trigger_gc": {
			ID:        "trigger_gc",
			Type:      "memory_cleanup",
			Component: "gc",
			Parameters: map[string]interface{}{
				"force": true,
			},
			Impact: OptimizationImpact{
				CPU:        5.0,
				Memory:     -20.0,
				Throughput: -2.0,
				Latency:    3.0,
				Confidence: 0.95,
			},
			Duration:   time.Millisecond * 100,
			Reversible: false,
			RiskLevel:  0.05,
		},
		"reduce_allocations": {
			ID:        "reduce_allocations",
			Type:      "memory_optimize",
			Component: "runtime",
			Parameters: map[string]interface{}{
				"pool_size": 1000,
			},
			Impact: OptimizationImpact{
				CPU:        -5.0,
				Memory:     -15.0,
				Throughput: 3.0,
				Latency:    -2.0,
				Confidence: 0.7,
			},
			Duration:   time.Second * 10,
			Reversible: true,
			RiskLevel:  0.25,
		},
		"increase_workers": {
			ID:        "increase_workers",
			Type:      "scale_up",
			Component: "worker_pool",
			Parameters: map[string]interface{}{
				"scale_factor": 1.5,
			},
			Impact: OptimizationImpact{
				CPU:        20.0,
				Memory:     15.0,
				Throughput: -25.0,
				Latency:    -15.0,
				Confidence: 0.9,
			},
			Duration:   time.Second * 3,
			Reversible: true,
			RiskLevel:  0.3,
		},
		"optimize_batch_size": {
			ID:        "optimize_batch_size",
			Type:      "batch_tune",
			Component: "processor",
			Parameters: map[string]interface{}{
				"new_batch_size": 500,
			},
			Impact: OptimizationImpact{
				CPU:        -8.0,
				Memory:     -5.0,
				Throughput: -18.0,
				Latency:    -10.0,
				Confidence: 0.75,
			},
			Duration:   time.Second * 1,
			Reversible: true,
			RiskLevel:  0.2,
		},
	}
	
	for id, action := range actions {
		po.actions[id] = action
	}
}