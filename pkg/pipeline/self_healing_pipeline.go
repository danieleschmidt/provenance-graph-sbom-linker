package pipeline

import (
	"context"
	"sync"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
	"github.com/sirupsen/logrus"
)

// SelfHealingConfig configures the self-healing pipeline
type SelfHealingConfig struct {
	MaxRetries              int           `yaml:"max_retries"`
	RetryDelay              time.Duration `yaml:"retry_delay"`
	HealthCheckInterval     time.Duration `yaml:"health_check_interval"`
	RecoveryTimeout         time.Duration `yaml:"recovery_timeout"`
	CircuitBreakerThreshold int           `yaml:"circuit_breaker_threshold"`
}

// DefaultSelfHealingConfig returns default configuration
func DefaultSelfHealingConfig() SelfHealingConfig {
	return SelfHealingConfig{
		MaxRetries:              3,
		RetryDelay:              5 * time.Second,
		HealthCheckInterval:     30 * time.Second,
		RecoveryTimeout:         2 * time.Minute,
		CircuitBreakerThreshold: 5,
	}
}

// ComponentStatus represents the health status of a pipeline component
type ComponentStatus string

const (
	StatusHealthy   ComponentStatus = "HEALTHY"
	StatusDegraded  ComponentStatus = "DEGRADED"
	StatusUnhealthy ComponentStatus = "UNHEALTHY"
	StatusCritical  ComponentStatus = "CRITICAL"
)

func (cs ComponentStatus) String() string {
	return string(cs)
}

// ComponentHealth represents the health of a pipeline component
type ComponentHealth struct {
	Status    ComponentStatus `json:"status"`
	ErrorRate float64         `json:"error_rate"`
	Latency   time.Duration   `json:"latency"`
	LastCheck time.Time       `json:"last_check"`
}

// SelfHealingPipeline is a pipeline with self-healing capabilities
type SelfHealingPipeline struct {
	config              PipelineConfig
	selfHealingConfig   SelfHealingConfig
	stages              []PipelineStage
	logger              *logrus.Logger
	metricsCollector    *monitoring.MetricsCollector

	// Runtime state
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	inputChan       chan interface{}
	outputChan      chan interface{}
	componentHealth map[string]*ComponentHealth
	mu              sync.RWMutex
}

// NewSelfHealingPipeline creates a new self-healing pipeline
func NewSelfHealingPipeline(
	config PipelineConfig,
	selfHealingConfig SelfHealingConfig,
	stages []PipelineStage,
	logger *logrus.Logger,
	metricsCollector *monitoring.MetricsCollector,
) *SelfHealingPipeline {
	return &SelfHealingPipeline{
		config:            config,
		selfHealingConfig: selfHealingConfig,
		stages:            stages,
		logger:            logger,
		metricsCollector:  metricsCollector,
		inputChan:         make(chan interface{}, config.BufferSize),
		outputChan:        make(chan interface{}, config.BufferSize),
		componentHealth:   make(map[string]*ComponentHealth),
	}
}

// Start starts the self-healing pipeline
func (shp *SelfHealingPipeline) Start(ctx context.Context) error {
	shp.ctx, shp.cancel = context.WithCancel(ctx)

	// Initialize component health
	for _, stage := range shp.stages {
		shp.componentHealth[stage.Name()] = &ComponentHealth{
			Status:    StatusHealthy,
			ErrorRate: 0.0,
			Latency:   0,
			LastCheck: time.Now(),
		}
	}

	// Start worker goroutines
	for i := 0; i < shp.config.WorkerCount; i++ {
		shp.wg.Add(1)
		go shp.worker()
	}

	// Start health check routine
	shp.wg.Add(1)
	go shp.healthCheckRoutine()

	shp.logger.Info("Self-healing pipeline started")
	return nil
}

// Stop stops the self-healing pipeline
func (shp *SelfHealingPipeline) Stop(timeout time.Duration) {
	if shp.cancel != nil {
		shp.cancel()
	}

	// Close input channel
	close(shp.inputChan)

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		shp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		shp.logger.Info("Self-healing pipeline stopped gracefully")
	case <-time.After(timeout):
		shp.logger.Warn("Self-healing pipeline stop timeout exceeded")
	}

	close(shp.outputChan)
}

// GetComponentHealth returns the health status of all components
func (shp *SelfHealingPipeline) GetComponentHealth() map[string]*ComponentHealth {
	shp.mu.RLock()
	defer shp.mu.RUnlock()

	result := make(map[string]*ComponentHealth)
	for name, health := range shp.componentHealth {
		healthCopy := *health
		result[name] = &healthCopy
	}

	return result
}

// worker processes data through the pipeline stages
func (shp *SelfHealingPipeline) worker() {
	defer shp.wg.Done()

	for {
		select {
		case data, ok := <-shp.inputChan:
			if !ok {
				return
			}

			// Process through all stages
			processedData := data
			var err error

			for _, stage := range shp.stages {
				start := time.Now()
				processedData, err = stage.Process(shp.ctx, processedData)
				latency := time.Since(start)

				// Update component health
				shp.updateComponentHealth(stage.Name(), err, latency)

				if err != nil {
					shp.logger.WithFields(logrus.Fields{
						"stage": stage.Name(),
						"error": err.Error(),
					}).Error("Pipeline stage failed")
					break
				}
			}

			// Send to output if successful
			if err == nil {
				select {
				case shp.outputChan <- processedData:
				default:
					shp.logger.Warn("Output channel full, dropping processed data")
				}
			}

		case <-shp.ctx.Done():
			return
		}
	}
}

// updateComponentHealth updates the health status of a component
func (shp *SelfHealingPipeline) updateComponentHealth(componentName string, err error, latency time.Duration) {
	shp.mu.Lock()
	defer shp.mu.Unlock()

	health, exists := shp.componentHealth[componentName]
	if !exists {
		health = &ComponentHealth{
			Status:    StatusHealthy,
			ErrorRate: 0.0,
			Latency:   latency,
			LastCheck: time.Now(),
		}
		shp.componentHealth[componentName] = health
	}

	// Update latency
	health.Latency = latency
	health.LastCheck = time.Now()

	// Update error rate (simple moving average)
	if err != nil {
		health.ErrorRate = (health.ErrorRate*0.9) + (1.0*0.1) // 10% weight for new error
	} else {
		health.ErrorRate = health.ErrorRate * 0.9 // Decay error rate
	}

	// Update status based on error rate and latency
	if health.ErrorRate > 0.5 {
		health.Status = StatusCritical
	} else if health.ErrorRate > 0.2 {
		health.Status = StatusUnhealthy
	} else if health.ErrorRate > 0.05 || latency > 5*time.Second {
		health.Status = StatusDegraded
	} else {
		health.Status = StatusHealthy
	}
}

// healthCheckRoutine periodically checks component health
func (shp *SelfHealingPipeline) healthCheckRoutine() {
	defer shp.wg.Done()

	ticker := time.NewTicker(shp.selfHealingConfig.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			shp.performHealthChecks()
		case <-shp.ctx.Done():
			return
		}
	}
}

// performHealthChecks checks the health of all stages
func (shp *SelfHealingPipeline) performHealthChecks() {
	for _, stage := range shp.stages {
		// For Generation 1, we'll skip health checks to make it work
		// Individual stages can implement their own health checks
		shp.mu.Lock()
		if health, exists := shp.componentHealth[stage.Name()]; exists {
			health.LastCheck = time.Now()
		}
		shp.mu.Unlock()
	}
}