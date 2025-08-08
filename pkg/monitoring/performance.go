package monitoring

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// PerformanceMonitor tracks application performance metrics
type PerformanceMonitor struct {
	meter   metric.Meter
	tracer  trace.Tracer
	
	// Metrics
	requestCounter    metric.Int64Counter
	requestDuration   metric.Float64Histogram
	errorCounter      metric.Int64Counter
	memoryGauge       metric.Int64ObservableGauge
	goroutineGauge    metric.Int64ObservableGauge
	
	// Custom metrics
	customMetrics map[string]interface{}
	mutex         sync.RWMutex
	
	// Performance data collection
	samples    []PerformanceSample
	sampleSize int
}

// PerformanceSample represents a performance measurement
type PerformanceSample struct {
	Timestamp     time.Time     `json:"timestamp"`
	Operation     string        `json:"operation"`
	Duration      time.Duration `json:"duration"`
	Success       bool          `json:"success"`
	MemoryUsage   int64         `json:"memory_usage"`
	GoroutineCount int          `json:"goroutine_count"`
	CPUUsage      float64       `json:"cpu_usage"`
	Labels        map[string]string `json:"labels"`
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(serviceName string) (*PerformanceMonitor, error) {
	meter := otel.Meter(serviceName)
	tracer := otel.Tracer(serviceName)

	// Initialize metrics
	requestCounter, err := meter.Int64Counter(
		"requests_total",
		metric.WithDescription("Total number of requests"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request counter: %w", err)
	}

	requestDuration, err := meter.Float64Histogram(
		"request_duration_seconds",
		metric.WithDescription("Request duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request duration histogram: %w", err)
	}

	errorCounter, err := meter.Int64Counter(
		"errors_total",
		metric.WithDescription("Total number of errors"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create error counter: %w", err)
	}

	memoryGauge, err := meter.Int64ObservableGauge(
		"memory_usage_bytes",
		metric.WithDescription("Memory usage in bytes"),
		metric.WithUnit("bytes"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create memory gauge: %w", err)
	}

	goroutineGauge, err := meter.Int64ObservableGauge(
		"goroutines_active",
		metric.WithDescription("Number of active goroutines"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create goroutine gauge: %w", err)
	}

	pm := &PerformanceMonitor{
		meter:             meter,
		tracer:            tracer,
		requestCounter:    requestCounter,
		requestDuration:   requestDuration,
		errorCounter:      errorCounter,
		memoryGauge:       memoryGauge,
		goroutineGauge:    goroutineGauge,
		customMetrics:     make(map[string]interface{}),
		sampleSize:        1000,
		samples:           make([]PerformanceSample, 0, 1000),
	}

	// Register callbacks for observables
	_, err = meter.RegisterCallback(pm.updateSystemMetrics, memoryGauge, goroutineGauge)
	if err != nil {
		return nil, fmt.Errorf("failed to register callback: %w", err)
	}

	return pm, nil
}

// TrackOperation tracks the performance of an operation
func (pm *PerformanceMonitor) TrackOperation(ctx context.Context, operation string, fn func(ctx context.Context) error) error {
	start := time.Now()
	
	// Create span for tracing
	ctx, span := pm.tracer.Start(ctx, operation)
	defer span.End()
	
	// Add operation to span attributes
	span.SetAttributes(attribute.String("operation", operation))
	
	var err error
	var success bool = true
	
	defer func() {
		duration := time.Since(start)
		
		// Record metrics
		pm.requestCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", operation),
			attribute.Bool("success", success),
		))
		
		pm.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(
			attribute.String("operation", operation),
		))
		
		if !success {
			pm.errorCounter.Add(ctx, 1, metric.WithAttributes(
				attribute.String("operation", operation),
			))
		}
		
		// Collect performance sample
		pm.collectSample(operation, duration, success, map[string]string{
			"success": fmt.Sprintf("%t", success),
		})
		
		// Add span attributes
		span.SetAttributes(
			attribute.Float64("duration_seconds", duration.Seconds()),
			attribute.Bool("success", success),
		)
		
		if err != nil {
			span.RecordError(err)
		}
	}()
	
	// Execute the operation
	err = fn(ctx)
	if err != nil {
		success = false
	}
	
	return err
}

// TrackDuration records a duration metric
func (pm *PerformanceMonitor) TrackDuration(ctx context.Context, operation string, duration time.Duration, labels map[string]string) {
	attrs := []attribute.KeyValue{
		attribute.String("operation", operation),
	}
	
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	
	pm.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
	pm.collectSample(operation, duration, true, labels)
}

// TrackCounter increments a counter metric
func (pm *PerformanceMonitor) TrackCounter(ctx context.Context, name string, value int64, labels map[string]string) {
	attrs := []attribute.KeyValue{}
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	
	pm.requestCounter.Add(ctx, value, metric.WithAttributes(attrs...))
}

// TrackError records an error
func (pm *PerformanceMonitor) TrackError(ctx context.Context, operation string, err error, labels map[string]string) {
	attrs := []attribute.KeyValue{
		attribute.String("operation", operation),
		attribute.String("error_type", fmt.Sprintf("%T", err)),
	}
	
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	
	pm.errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	
	// Create span for error
	_, span := pm.tracer.Start(ctx, "error_"+operation)
	span.RecordError(err)
	span.End()
}

// collectSample adds a performance sample to the collection
func (pm *PerformanceMonitor) collectSample(operation string, duration time.Duration, success bool, labels map[string]string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	sample := PerformanceSample{
		Timestamp:      time.Now(),
		Operation:      operation,
		Duration:       duration,
		Success:        success,
		MemoryUsage:    int64(m.Alloc),
		GoroutineCount: runtime.NumGoroutine(),
		Labels:         labels,
	}
	
	if len(pm.samples) >= pm.sampleSize {
		// Remove oldest sample
		pm.samples = pm.samples[1:]
	}
	
	pm.samples = append(pm.samples, sample)
}

// updateSystemMetrics updates system-level metrics
func (pm *PerformanceMonitor) updateSystemMetrics(ctx context.Context, observer metric.Observer) error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	observer.ObserveInt64(pm.memoryGauge, int64(m.Alloc))
	observer.ObserveInt64(pm.goroutineGauge, int64(runtime.NumGoroutine()))
	
	return nil
}

// GetPerformanceStats returns current performance statistics
func (pm *PerformanceMonitor) GetPerformanceStats() *PerformanceStats {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	if len(pm.samples) == 0 {
		return &PerformanceStats{}
	}
	
	stats := &PerformanceStats{
		TotalRequests: int64(len(pm.samples)),
		SamplePeriod:  time.Since(pm.samples[0].Timestamp),
	}
	
	var totalDuration time.Duration
	var successCount int64
	var durations []time.Duration
	
	operationStats := make(map[string]*OperationStats)
	
	for _, sample := range pm.samples {
		totalDuration += sample.Duration
		durations = append(durations, sample.Duration)
		
		if sample.Success {
			successCount++
		}
		
		// Per-operation statistics
		opStats, exists := operationStats[sample.Operation]
		if !exists {
			opStats = &OperationStats{
				Operation: sample.Operation,
			}
			operationStats[sample.Operation] = opStats
		}
		
		opStats.TotalRequests++
		opStats.TotalDuration += sample.Duration
		
		if sample.Success {
			opStats.SuccessCount++
		}
		
		if sample.Duration > opStats.MaxDuration {
			opStats.MaxDuration = sample.Duration
		}
		
		if opStats.MinDuration == 0 || sample.Duration < opStats.MinDuration {
			opStats.MinDuration = sample.Duration
		}
	}
	
	// Calculate overall statistics
	stats.SuccessRate = float64(successCount) / float64(len(pm.samples))
	stats.AverageDuration = totalDuration / time.Duration(len(pm.samples))
	stats.RequestRate = float64(len(pm.samples)) / stats.SamplePeriod.Seconds()
	
	// Calculate percentiles
	if len(durations) > 0 {
		stats.P50Duration = calculatePercentile(durations, 0.5)
		stats.P95Duration = calculatePercentile(durations, 0.95)
		stats.P99Duration = calculatePercentile(durations, 0.99)
	}
	
	// Add operation statistics
	stats.Operations = make([]*OperationStats, 0, len(operationStats))
	for _, opStats := range operationStats {
		opStats.SuccessRate = float64(opStats.SuccessCount) / float64(opStats.TotalRequests)
		opStats.AverageDuration = opStats.TotalDuration / time.Duration(opStats.TotalRequests)
		stats.Operations = append(stats.Operations, opStats)
	}
	
	return stats
}

// GetMemoryStats returns current memory statistics
func (pm *PerformanceMonitor) GetMemoryStats() *MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	return &MemoryStats{
		Alloc:         m.Alloc,
		TotalAlloc:    m.TotalAlloc,
		Sys:           m.Sys,
		NumGC:         m.NumGC,
		GoroutineCount: runtime.NumGoroutine(),
		NextGC:        m.NextGC,
		LastGC:        time.Unix(0, int64(m.LastGC)),
		PauseTotalNs:  m.PauseTotalNs,
	}
}

// CreateSpan creates a new tracing span
func (pm *PerformanceMonitor) CreateSpan(ctx context.Context, operation string, attributes map[string]interface{}) (context.Context, trace.Span) {
	attrs := []attribute.KeyValue{}
	for k, v := range attributes {
		switch val := v.(type) {
		case string:
			attrs = append(attrs, attribute.String(k, val))
		case int:
			attrs = append(attrs, attribute.Int(k, val))
		case int64:
			attrs = append(attrs, attribute.Int64(k, val))
		case float64:
			attrs = append(attrs, attribute.Float64(k, val))
		case bool:
			attrs = append(attrs, attribute.Bool(k, val))
		default:
			attrs = append(attrs, attribute.String(k, fmt.Sprintf("%v", val)))
		}
	}
	
	ctx, span := pm.tracer.Start(ctx, operation, trace.WithAttributes(attrs...))
	return ctx, span
}

// Performance statistics structures
type PerformanceStats struct {
	TotalRequests   int64             `json:"total_requests"`
	SuccessRate     float64           `json:"success_rate"`
	RequestRate     float64           `json:"request_rate_per_second"`
	AverageDuration time.Duration     `json:"average_duration"`
	P50Duration     time.Duration     `json:"p50_duration"`
	P95Duration     time.Duration     `json:"p95_duration"`
	P99Duration     time.Duration     `json:"p99_duration"`
	SamplePeriod    time.Duration     `json:"sample_period"`
	Operations      []*OperationStats `json:"operations"`
}

type OperationStats struct {
	Operation       string        `json:"operation"`
	TotalRequests   int64         `json:"total_requests"`
	SuccessCount    int64         `json:"success_count"`
	SuccessRate     float64       `json:"success_rate"`
	TotalDuration   time.Duration `json:"total_duration"`
	AverageDuration time.Duration `json:"average_duration"`
	MinDuration     time.Duration `json:"min_duration"`
	MaxDuration     time.Duration `json:"max_duration"`
}

type MemoryStats struct {
	Alloc          uint64    `json:"alloc_bytes"`
	TotalAlloc     uint64    `json:"total_alloc_bytes"`
	Sys            uint64    `json:"sys_bytes"`
	NumGC          uint32    `json:"num_gc"`
	GoroutineCount int       `json:"goroutine_count"`
	NextGC         uint64    `json:"next_gc_bytes"`
	LastGC         time.Time `json:"last_gc_time"`
	PauseTotalNs   uint64    `json:"pause_total_ns"`
}

// calculatePercentile calculates the nth percentile of a slice of durations
func calculatePercentile(durations []time.Duration, percentile float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	// Simple sorting for percentile calculation
	// In production, use a more efficient algorithm
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	
	// Bubble sort (simple but inefficient - use sort.Slice in production)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	
	index := int(float64(len(sorted)-1) * percentile)
	return sorted[index]
}

// AlertManager handles performance-based alerts
type AlertManager struct {
	thresholds map[string]AlertThreshold
	callbacks  map[string]AlertCallback
	mutex      sync.RWMutex
}

type AlertThreshold struct {
	MetricName    string        `json:"metric_name"`
	Threshold     float64       `json:"threshold"`
	Duration      time.Duration `json:"duration"`
	Condition     string        `json:"condition"` // "greater_than", "less_than", "equals"
}

type AlertCallback func(alert Alert)

type Alert struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Timestamp   time.Time         `json:"timestamp"`
	Value       float64           `json:"value"`
	Threshold   float64           `json:"threshold"`
	Labels      map[string]string `json:"labels"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager() *AlertManager {
	return &AlertManager{
		thresholds: make(map[string]AlertThreshold),
		callbacks:  make(map[string]AlertCallback),
	}
}

// RegisterThreshold registers a performance threshold
func (am *AlertManager) RegisterThreshold(name string, threshold AlertThreshold) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	am.thresholds[name] = threshold
}

// RegisterCallback registers an alert callback
func (am *AlertManager) RegisterCallback(name string, callback AlertCallback) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	am.callbacks[name] = callback
}

// CheckThresholds checks current metrics against thresholds
func (am *AlertManager) CheckThresholds(stats *PerformanceStats) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	
	for name, threshold := range am.thresholds {
		value := am.getMetricValue(stats, threshold.MetricName)
		
		if am.shouldAlert(value, threshold) {
			alert := Alert{
				Name:        name,
				Description: fmt.Sprintf("Performance threshold exceeded for %s", threshold.MetricName),
				Severity:    "warning",
				Timestamp:   time.Now(),
				Value:       value,
				Threshold:   threshold.Threshold,
				Labels: map[string]string{
					"metric": threshold.MetricName,
				},
			}
			
			if callback, exists := am.callbacks[name]; exists {
				go callback(alert)
			}
		}
	}
}

// getMetricValue extracts a metric value from performance stats
func (am *AlertManager) getMetricValue(stats *PerformanceStats, metricName string) float64 {
	switch metricName {
	case "success_rate":
		return stats.SuccessRate
	case "request_rate":
		return stats.RequestRate
	case "average_duration_ms":
		return float64(stats.AverageDuration.Nanoseconds()) / 1e6
	case "p95_duration_ms":
		return float64(stats.P95Duration.Nanoseconds()) / 1e6
	case "p99_duration_ms":
		return float64(stats.P99Duration.Nanoseconds()) / 1e6
	default:
		return 0
	}
}

// shouldAlert determines if an alert should be triggered
func (am *AlertManager) shouldAlert(value float64, threshold AlertThreshold) bool {
	switch threshold.Condition {
	case "greater_than":
		return value > threshold.Threshold
	case "less_than":
		return value < threshold.Threshold
	case "equals":
		return value == threshold.Threshold
	default:
		return false
	}
}

// ResourceMonitor monitors system resources
type ResourceMonitor struct {
	cpuUsage    float64
	memoryUsage float64
	diskUsage   float64
	networkIO   int64
	mutex       sync.RWMutex
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor() *ResourceMonitor {
	return &ResourceMonitor{}
}

// Start begins resource monitoring
func (rm *ResourceMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			rm.updateResourceMetrics()
		case <-ctx.Done():
			return
		}
	}
}

// updateResourceMetrics updates resource usage metrics
func (rm *ResourceMonitor) updateResourceMetrics() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	// Update CPU usage (simplified - use proper CPU monitoring in production)
	rm.cpuUsage = rm.getCurrentCPUUsage()
	
	// Update memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	rm.memoryUsage = float64(m.Alloc) / float64(m.Sys) * 100
	
	// Update disk and network usage (simplified)
	rm.diskUsage = 0  // Implement disk usage monitoring
	rm.networkIO = 0  // Implement network I/O monitoring
}

// getCurrentCPUUsage returns current CPU usage percentage
func (rm *ResourceMonitor) getCurrentCPUUsage() float64 {
	// Simplified CPU usage calculation
	// In production, use proper CPU monitoring libraries
	return float64(runtime.NumGoroutine()) / 1000.0 * 100
}

// GetResourceStats returns current resource statistics
func (rm *ResourceMonitor) GetResourceStats() *ResourceStats {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	return &ResourceStats{
		CPUUsage:    rm.cpuUsage,
		MemoryUsage: rm.memoryUsage,
		DiskUsage:   rm.diskUsage,
		NetworkIO:   rm.networkIO,
		Timestamp:   time.Now(),
	}
}

type ResourceStats struct {
	CPUUsage    float64   `json:"cpu_usage_percent"`
	MemoryUsage float64   `json:"memory_usage_percent"`
	DiskUsage   float64   `json:"disk_usage_percent"`
	NetworkIO   int64     `json:"network_io_bytes"`
	Timestamp   time.Time `json:"timestamp"`
}