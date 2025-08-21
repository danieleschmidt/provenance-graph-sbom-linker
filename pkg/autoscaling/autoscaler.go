package autoscaling

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
	"github.com/sirupsen/logrus"
)

type ScalingConfig struct {
	CPUThreshold            float64       `yaml:"cpu_threshold"`
	MemoryThreshold         float64       `yaml:"memory_threshold"`
	QueueThreshold          float64       `yaml:"queue_threshold"`
	ScaleUpCooldown         time.Duration `yaml:"scale_up_cooldown"`
	ScaleDownCooldown       time.Duration `yaml:"scale_down_cooldown"`
	MaxReplicas             int           `yaml:"max_replicas"`
	MinReplicas             int           `yaml:"min_replicas"`
	MetricsWindow           time.Duration `yaml:"metrics_window"`
	PredictiveScalingWindow time.Duration `yaml:"predictive_scaling_window"`
}

func DefaultScalingConfig() ScalingConfig {
	return ScalingConfig{
		CPUThreshold:            75.0,
		MemoryThreshold:         80.0,
		QueueThreshold:          0.8,
		ScaleUpCooldown:         2 * time.Minute,
		ScaleDownCooldown:       5 * time.Minute,
		MaxReplicas:             10,
		MinReplicas:             2,
		MetricsWindow:           5 * time.Minute,
		PredictiveScalingWindow: 15 * time.Minute,
	}
}

type ScalingDecision struct {
	Action      string    `json:"action"`
	Reason      string    `json:"reason"`
	FromCount   int       `json:"from_count"`
	ToCount     int       `json:"to_count"`
	Timestamp   time.Time `json:"timestamp"`
	Confidence  float64   `json:"confidence"`
	MetricValue float64   `json:"metric_value"`
}

type IntelligentScaler struct {
	config           ScalingConfig
	metricsCollector *monitoring.MetricsCollector
	currentReplicas  int
	lastScaleUp      time.Time
	lastScaleDown    time.Time
	logger           *logrus.Logger
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	mu               sync.RWMutex
}

func NewIntelligentScaler(config ScalingConfig, metricsCollector *monitoring.MetricsCollector, initialReplicas int, logger *logrus.Logger) *IntelligentScaler {
	return &IntelligentScaler{
		config:           config,
		metricsCollector: metricsCollector,
		currentReplicas:  initialReplicas,
		logger:           logger,
	}
}

func (s *IntelligentScaler) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	
	s.wg.Add(1)
	go s.scalingLoop()
	
	s.logger.Info("Intelligent autoscaler started")
	return nil
}

func (s *IntelligentScaler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	s.logger.Info("Intelligent autoscaler stopped")
}

func (s *IntelligentScaler) scalingLoop() {
	defer s.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			s.evaluateScaling()
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *IntelligentScaler) evaluateScaling() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	metrics := s.metricsCollector.GetApplicationMetrics()
	
	// Check if we need to scale up
	if s.shouldScaleUp(metrics) {
		newReplicas := s.currentReplicas + 1
		if newReplicas <= s.config.MaxReplicas {
			decision := ScalingDecision{
				Action:      "scale_up",
				Reason:      fmt.Sprintf("CPU: %.2f%%, Memory: %.2f%%", metrics.CPUUsagePercent, metrics.MemoryUsageMB),
				FromCount:   s.currentReplicas,
				ToCount:     newReplicas,
				Timestamp:   time.Now(),
				Confidence:  s.calculateConfidence(metrics),
				MetricValue: metrics.CPUUsagePercent,
			}
			
			s.executeScaling(decision)
		}
	}
	
	// Check if we need to scale down
	if s.shouldScaleDown(metrics) {
		newReplicas := s.currentReplicas - 1
		if newReplicas >= s.config.MinReplicas {
			decision := ScalingDecision{
				Action:      "scale_down",
				Reason:      fmt.Sprintf("Low resource usage - CPU: %.2f%%, Memory: %.2f%%", metrics.CPUUsagePercent, metrics.MemoryUsageMB),
				FromCount:   s.currentReplicas,
				ToCount:     newReplicas,
				Timestamp:   time.Now(),
				Confidence:  s.calculateConfidence(metrics),
				MetricValue: metrics.CPUUsagePercent,
			}
			
			s.executeScaling(decision)
		}
	}
}

func (s *IntelligentScaler) shouldScaleUp(metrics *monitoring.ApplicationMetrics) bool {
	if time.Since(s.lastScaleUp) < s.config.ScaleUpCooldown {
		return false
	}
	
	return metrics.CPUUsagePercent > s.config.CPUThreshold ||
		   metrics.MemoryUsageMB/1024 > s.config.MemoryThreshold
}

func (s *IntelligentScaler) shouldScaleDown(metrics *monitoring.ApplicationMetrics) bool {
	if time.Since(s.lastScaleDown) < s.config.ScaleDownCooldown {
		return false
	}
	
	return metrics.CPUUsagePercent < s.config.CPUThreshold*0.5 &&
		   metrics.MemoryUsageMB/1024 < s.config.MemoryThreshold*0.5
}

func (s *IntelligentScaler) calculateConfidence(metrics *monitoring.ApplicationMetrics) float64 {
	// Simple confidence calculation based on metric stability
	if metrics.CPUUsagePercent > s.config.CPUThreshold*1.5 {
		return 0.9
	}
	return 0.7
}

func (s *IntelligentScaler) executeScaling(decision ScalingDecision) {
	s.logger.WithFields(logrus.Fields{
		"action":       decision.Action,
		"from_count":   decision.FromCount,
		"to_count":     decision.ToCount,
		"reason":       decision.Reason,
		"confidence":   decision.Confidence,
	}).Info("Executing scaling decision")
	
	s.currentReplicas = decision.ToCount
	
	if decision.Action == "scale_up" {
		s.lastScaleUp = time.Now()
	} else {
		s.lastScaleDown = time.Now()
	}
}

func (s *IntelligentScaler) GetCurrentReplicas() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentReplicas
}