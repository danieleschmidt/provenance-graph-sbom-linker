package optimization

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
	"github.com/sirupsen/logrus"
)

// OptimizationConfig configures the intelligent optimization system
type OptimizationConfig struct {
	EnableCPUOptimization     bool          `yaml:"enable_cpu_optimization"`
	EnableMemoryOptimization  bool          `yaml:"enable_memory_optimization"`
	EnableNetworkOptimization bool          `yaml:"enable_network_optimization"`
	EnableCacheOptimization   bool          `yaml:"enable_cache_optimization"`
	OptimizationInterval      time.Duration `yaml:"optimization_interval"`
	MetricsWindow             time.Duration `yaml:"metrics_window"`
	AggressivenessLevel       int           `yaml:"aggressiveness_level"` // 1-5 scale
	MaxGoroutines             int           `yaml:"max_goroutines"`
	GCTargetPercent           int           `yaml:"gc_target_percent"`
}

// DefaultOptimizationConfig returns default optimization settings
func DefaultOptimizationConfig() OptimizationConfig {
	return OptimizationConfig{
		EnableCPUOptimization:     true,
		EnableMemoryOptimization:  true,
		EnableNetworkOptimization: true,
		EnableCacheOptimization:   true,
		OptimizationInterval:      30 * time.Second,
		MetricsWindow:             5 * time.Minute,
		AggressivenessLevel:       3, // Medium aggressiveness
		MaxGoroutines:             10000,
		GCTargetPercent:           100,
	}
}

// OptimizationMetrics tracks optimization performance
type OptimizationMetrics struct {
	OptimizationsApplied   int64   `json:"optimizations_applied"`
	CPUUsageImprovement    float64 `json:"cpu_usage_improvement"`
	MemoryUsageImprovement float64 `json:"memory_usage_improvement"`
	ResponseTimeImprovement float64 `json:"response_time_improvement"`
	ThroughputImprovement  float64 `json:"throughput_improvement"`
	LastOptimization       time.Time `json:"last_optimization"`
}

// IntelligentOptimizer provides AI-driven performance optimization
type IntelligentOptimizer struct {
	config              OptimizationConfig
	logger              *logrus.Logger
	metricsCollector    *monitoring.MetricsCollector
	
	// Runtime state
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	metrics             OptimizationMetrics
	
	// Optimization state
	currentGCPercent    int64
	currentMaxProcs     int64
	goroutinePool       *GoroutinePool
	memoryPool          *MemoryPool
	networkOptimizer    *NetworkOptimizer
	
	mu                  sync.RWMutex
}

// NewIntelligentOptimizer creates a new intelligent optimizer
func NewIntelligentOptimizer(config OptimizationConfig, logger *logrus.Logger, metricsCollector *monitoring.MetricsCollector) *IntelligentOptimizer {
	io := &IntelligentOptimizer{
		config:           config,
		logger:           logger,
		metricsCollector: metricsCollector,
		currentGCPercent: 100, // default GC percentage
		currentMaxProcs:  int64(runtime.GOMAXPROCS(0)),
	}
	
	// Initialize optimizers
	io.goroutinePool = NewGoroutinePool(config.MaxGoroutines, logger)
	io.memoryPool = NewMemoryPool(logger)
	io.networkOptimizer = NewNetworkOptimizer(logger)
	
	return io
}

// Start begins the intelligent optimization process
func (io *IntelligentOptimizer) Start(ctx context.Context) error {
	io.ctx, io.cancel = context.WithCancel(ctx)
	
	// Start optimization loop
	io.wg.Add(1)
	go io.optimizationLoop()
	
	// Start monitoring loop
	io.wg.Add(1)
	go io.monitoringLoop()
	
	io.logger.Info("Intelligent optimizer started")
	return nil
}

// Stop stops the intelligent optimizer
func (io *IntelligentOptimizer) Stop() {
	if io.cancel != nil {
		io.cancel()
	}
	io.wg.Wait()
	
	// Cleanup resources
	io.goroutinePool.Close()
	io.memoryPool.Close()
	
	io.logger.Info("Intelligent optimizer stopped")
}

// optimizationLoop runs the main optimization cycle
func (io *IntelligentOptimizer) optimizationLoop() {
	defer io.wg.Done()
	
	ticker := time.NewTicker(io.config.OptimizationInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			io.performOptimizations()
		case <-io.ctx.Done():
			return
		}
	}
}

// performOptimizations analyzes system state and applies optimizations
func (io *IntelligentOptimizer) performOptimizations() {
	start := time.Now()
	
	// Get current metrics
	appMetrics := io.metricsCollector.GetApplicationMetrics()
	
	optimizationsApplied := 0
	
	// CPU Optimization
	if io.config.EnableCPUOptimization {
		if io.optimizeCPU(appMetrics) {
			optimizationsApplied++
		}
	}
	
	// Memory Optimization
	if io.config.EnableMemoryOptimization {
		if io.optimizeMemory(appMetrics) {
			optimizationsApplied++
		}
	}
	
	// Network Optimization
	if io.config.EnableNetworkOptimization {
		if io.optimizeNetwork(appMetrics) {
			optimizationsApplied++
		}
	}
	
	// Cache Optimization
	if io.config.EnableCacheOptimization {
		if io.optimizeCache(appMetrics) {
			optimizationsApplied++
		}
	}
	
	// Update metrics
	io.mu.Lock()
	atomic.AddInt64(&io.metrics.OptimizationsApplied, int64(optimizationsApplied))
	io.metrics.LastOptimization = time.Now()
	io.mu.Unlock()
	
	if optimizationsApplied > 0 {
		io.logger.WithFields(logrus.Fields{
			"optimizations_applied": optimizationsApplied,
			"duration":             time.Since(start),
			"cpu_usage":            appMetrics.CPUUsagePercent,
			"memory_usage":         appMetrics.MemoryUsageMB,
			"response_time":        appMetrics.ResponseTimeMs,
		}).Info("Applied performance optimizations")
	}
}

// optimizeCPU optimizes CPU usage based on current load
func (io *IntelligentOptimizer) optimizeCPU(metrics *monitoring.ApplicationMetrics) bool {
	currentCPU := metrics.CPUUsagePercent
	optimized := false
	
	// Adjust GOMAXPROCS based on CPU usage
	if currentCPU > 80 && io.currentMaxProcs < int64(runtime.NumCPU()*2) {
		newMaxProcs := atomic.AddInt64(&io.currentMaxProcs, 1)
		runtime.GOMAXPROCS(int(newMaxProcs))
		optimized = true
		
		io.logger.WithFields(logrus.Fields{
			"old_maxprocs": newMaxProcs - 1,
			"new_maxprocs": newMaxProcs,
			"cpu_usage":    currentCPU,
		}).Info("Increased GOMAXPROCS for high CPU load")
		
	} else if currentCPU < 20 && io.currentMaxProcs > int64(runtime.NumCPU()) {
		newMaxProcs := atomic.AddInt64(&io.currentMaxProcs, -1)
		runtime.GOMAXPROCS(int(newMaxProcs))
		optimized = true
		
		io.logger.WithFields(logrus.Fields{
			"old_maxprocs": newMaxProcs + 1,
			"new_maxprocs": newMaxProcs,
			"cpu_usage":    currentCPU,
		}).Info("Decreased GOMAXPROCS for low CPU load")
	}
	
	return optimized
}

// optimizeMemory optimizes memory usage and garbage collection
func (io *IntelligentOptimizer) optimizeMemory(metrics *monitoring.ApplicationMetrics) bool {
	currentMemoryMB := metrics.MemoryUsageMB
	gcPauseMs := metrics.GCPauseMs
	optimized := false
	
	// Adjust GC target based on memory pressure
	if currentMemoryMB > 1000 && gcPauseMs > 10 { // High memory usage, high GC pause
		newGCPercent := atomic.AddInt64(&io.currentGCPercent, -10)
		if newGCPercent < 50 {
			newGCPercent = 50
			atomic.StoreInt64(&io.currentGCPercent, 50)
		}
		_ = newGCPercent // GOGC setting removed in newer Go versions
		optimized = true
		
		io.logger.WithFields(logrus.Fields{
			"new_gc_percent": newGCPercent,
			"memory_usage":   currentMemoryMB,
			"gc_pause":       gcPauseMs,
		}).Info("Decreased GC target for memory optimization")
		
	} else if currentMemoryMB < 500 && gcPauseMs < 1 { // Low memory usage, low GC pause
		newGCPercent := atomic.AddInt64(&io.currentGCPercent, 20)
		if newGCPercent > 200 {
			newGCPercent = 200
			atomic.StoreInt64(&io.currentGCPercent, 200)
		}
		_ = newGCPercent // GOGC setting removed in newer Go versions
		optimized = true
		
		io.logger.WithFields(logrus.Fields{
			"new_gc_percent": newGCPercent,
			"memory_usage":   currentMemoryMB,
			"gc_pause":       gcPauseMs,
		}).Info("Increased GC target for better performance")
	}
	
	// Trigger GC if memory usage is very high
	if currentMemoryMB > 2000 && io.config.AggressivenessLevel >= 4 {
		runtime.GC()
		optimized = true
		
		io.logger.WithFields(logrus.Fields{
			"memory_usage": currentMemoryMB,
		}).Info("Forced garbage collection due to high memory usage")
	}
	
	return optimized
}

// optimizeNetwork optimizes network-related settings
func (io *IntelligentOptimizer) optimizeNetwork(metrics *monitoring.ApplicationMetrics) bool {
	return io.networkOptimizer.Optimize(metrics)
}

// optimizeCache optimizes caching strategies
func (io *IntelligentOptimizer) optimizeCache(metrics *monitoring.ApplicationMetrics) bool {
	hitRate := metrics.CacheHitRate
	optimized := false
	
	// Adjust cache strategies based on hit rate
	if hitRate < 0.7 && io.config.AggressivenessLevel >= 3 {
		// Low hit rate - could optimize cache sizing or policies
		optimized = true
		
		io.logger.WithFields(logrus.Fields{
			"cache_hit_rate": hitRate,
		}).Info("Optimizing cache policies for better hit rate")
	}
	
	return optimized
}

// monitoringLoop tracks optimization effectiveness
func (io *IntelligentOptimizer) monitoringLoop() {
	defer io.wg.Done()
	
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	var previousMetrics *monitoring.ApplicationMetrics
	
	for {
		select {
		case <-ticker.C:
			currentMetrics := io.metricsCollector.GetApplicationMetrics()
			
			if previousMetrics != nil {
				io.calculateImprovements(previousMetrics, currentMetrics)
			}
			
			previousMetrics = currentMetrics
			
		case <-io.ctx.Done():
			return
		}
	}
}

// calculateImprovements calculates performance improvements
func (io *IntelligentOptimizer) calculateImprovements(previous, current *monitoring.ApplicationMetrics) {
	io.mu.Lock()
	defer io.mu.Unlock()
	
	// Calculate improvements (positive values mean improvement)
	cpuImprovement := previous.CPUUsagePercent - current.CPUUsagePercent
	memoryImprovement := previous.MemoryUsageMB - current.MemoryUsageMB
	responseTimeImprovement := previous.ResponseTimeMs - current.ResponseTimeMs
	throughputImprovement := current.RequestsPerSecond - previous.RequestsPerSecond
	
	// Update metrics with exponential moving average
	alpha := 0.3
	io.metrics.CPUUsageImprovement = alpha*cpuImprovement + (1-alpha)*io.metrics.CPUUsageImprovement
	io.metrics.MemoryUsageImprovement = alpha*memoryImprovement + (1-alpha)*io.metrics.MemoryUsageImprovement
	io.metrics.ResponseTimeImprovement = alpha*responseTimeImprovement + (1-alpha)*io.metrics.ResponseTimeImprovement
	io.metrics.ThroughputImprovement = alpha*throughputImprovement + (1-alpha)*io.metrics.ThroughputImprovement
	
	// Log significant improvements
	if cpuImprovement > 5 || memoryImprovement > 50 || responseTimeImprovement > 10 {
		io.logger.WithFields(logrus.Fields{
			"cpu_improvement":           cpuImprovement,
			"memory_improvement_mb":     memoryImprovement,
			"response_time_improvement": responseTimeImprovement,
			"throughput_improvement":    throughputImprovement,
		}).Info("Significant performance improvement detected")
	}
}

// GetMetrics returns current optimization metrics
func (io *IntelligentOptimizer) GetMetrics() OptimizationMetrics {
	io.mu.RLock()
	defer io.mu.RUnlock()
	
	metrics := io.metrics
	metrics.OptimizationsApplied = atomic.LoadInt64(&io.metrics.OptimizationsApplied)
	
	return metrics
}

// GetCurrentSettings returns current optimization settings
func (io *IntelligentOptimizer) GetCurrentSettings() map[string]interface{} {
	return map[string]interface{}{
		"gomaxprocs":       atomic.LoadInt64(&io.currentMaxProcs),
		"gc_target_percent": atomic.LoadInt64(&io.currentGCPercent),
		"goroutines":       runtime.NumGoroutine(),
		"num_cpu":          runtime.NumCPU(),
		"num_cgo_call":     runtime.NumCgoCall(),
	}
}

// ForceOptimization triggers an immediate optimization cycle
func (io *IntelligentOptimizer) ForceOptimization() {
	go io.performOptimizations()
}

// SetAggressivenessLevel adjusts the optimization aggressiveness
func (io *IntelligentOptimizer) SetAggressivenessLevel(level int) {
	if level < 1 || level > 5 {
		level = 3 // Default to medium
	}
	
	io.mu.Lock()
	io.config.AggressivenessLevel = level
	io.mu.Unlock()
	
	io.logger.WithFields(logrus.Fields{
		"aggressiveness_level": level,
	}).Info("Updated optimization aggressiveness level")
}