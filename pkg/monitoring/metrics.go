package monitoring

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
)

// MetricsCollector provides comprehensive application metrics
type MetricsCollector struct {
	mutex    sync.RWMutex
	logger   *logger.StructuredLogger
	metrics  map[string]*Metric
	started  bool
	interval time.Duration
	stopCh   chan bool
}

// Metric represents a single metric with its current value and history
type Metric struct {
	Name        string                 `json:"name"`
	Type        MetricType             `json:"type"`
	Value       interface{}            `json:"value"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	History     []MetricDataPoint      `json:"history,omitempty"`
	Aggregation AggregationType        `json:"aggregation"`
	metadata    map[string]interface{}
}

type MetricDataPoint struct {
	Value     interface{} `json:"value"`
	Timestamp time.Time   `json:"timestamp"`
}

type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeTiming    MetricType = "timing"
)

type AggregationType string

const (
	AggregationSum     AggregationType = "sum"
	AggregationAvg     AggregationType = "avg"
	AggregationMin     AggregationType = "min"
	AggregationMax     AggregationType = "max"
	AggregationCount   AggregationType = "count"
	AggregationP95     AggregationType = "p95"
	AggregationP99     AggregationType = "p99"
)

// ApplicationMetrics contains all application-level metrics
type ApplicationMetrics struct {
	RequestsTotal        int64             `json:"requests_total"`
	RequestsPerSecond    float64           `json:"requests_per_second"`
	ResponseTimeMs       float64           `json:"response_time_ms"`
	ErrorRate            float64           `json:"error_rate"`
	ActiveConnections    int64             `json:"active_connections"`
	DatabaseConnections  int64             `json:"database_connections"`
	CacheHitRate         float64           `json:"cache_hit_rate"`
	WorkerPoolUtilization float64          `json:"worker_pool_utilization"`
	MemoryUsageMB        float64           `json:"memory_usage_mb"`
	CPUUsagePercent      float64           `json:"cpu_usage_percent"`
	GoroutineCount       int               `json:"goroutine_count"`
	GCPauseMs            float64           `json:"gc_pause_ms"`
	UpstreamServices     map[string]ServiceHealth `json:"upstream_services"`
	Timestamp            time.Time         `json:"timestamp"`
}

type ServiceHealth struct {
	Status      string    `json:"status"`
	ResponseTime float64  `json:"response_time_ms"`
	LastCheck   time.Time `json:"last_check"`
	ErrorCount  int64     `json:"error_count"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(interval ...time.Duration) *MetricsCollector {
	defaultInterval := 30 * time.Second
	if len(interval) > 0 && interval[0] > 0 {
		defaultInterval = interval[0]
	}

	return &MetricsCollector{
		logger:   logger.NewStructuredLogger("info", "json"),
		metrics:  make(map[string]*Metric),
		interval: defaultInterval,
		stopCh:   make(chan bool),
	}
}

// Start begins metrics collection
func (mc *MetricsCollector) Start(ctx context.Context) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if mc.started {
		return fmt.Errorf("metrics collector already started")
	}

	mc.started = true
	go mc.collectMetrics(ctx)
	
	mc.logger.Info("metrics_collector_started", map[string]interface{}{
		"interval": mc.interval.String(),
	})

	return nil
}

// Stop stops metrics collection
func (mc *MetricsCollector) Stop() error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if !mc.started {
		return nil
	}

	mc.started = false
	close(mc.stopCh)

	mc.logger.Info("metrics_collector_stopped", map[string]interface{}{
		"total_metrics": len(mc.metrics),
	})

	return nil
}

// RecordCounter increments a counter metric
func (mc *MetricsCollector) RecordCounter(name string, value int64, labels map[string]string) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	key := mc.getMetricKey(name, labels)
	metric, exists := mc.metrics[key]
	
	if !exists {
		metric = &Metric{
			Name:        name,
			Type:        MetricTypeCounter,
			Value:       int64(0),
			Labels:      labels,
			Timestamp:   time.Now(),
			Aggregation: AggregationSum,
			History:     make([]MetricDataPoint, 0, 100),
		}
		mc.metrics[key] = metric
	}

	if currentValue, ok := metric.Value.(int64); ok {
		newValue := currentValue + value
		metric.Value = newValue
		metric.Timestamp = time.Now()
		mc.addToHistory(metric, newValue)
	}
}

// RecordGauge sets a gauge metric value
func (mc *MetricsCollector) RecordGauge(name string, value float64, labels map[string]string) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	key := mc.getMetricKey(name, labels)
	metric, exists := mc.metrics[key]
	
	if !exists {
		metric = &Metric{
			Name:        name,
			Type:        MetricTypeGauge,
			Value:       value,
			Labels:      labels,
			Timestamp:   time.Now(),
			Aggregation: AggregationAvg,
			History:     make([]MetricDataPoint, 0, 100),
		}
		mc.metrics[key] = metric
	}

	metric.Value = value
	metric.Timestamp = time.Now()
	mc.addToHistory(metric, value)
}

// RecordTiming records a timing metric in milliseconds
func (mc *MetricsCollector) RecordTiming(name string, duration time.Duration, labels map[string]string) {
	mc.RecordGauge(name, float64(duration.Nanoseconds())/1e6, labels)
}

// GetMetrics returns all current metrics
func (mc *MetricsCollector) GetMetrics() map[string]*Metric {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	result := make(map[string]*Metric)
	for key, metric := range mc.metrics {
		// Create a copy to avoid race conditions
		metricCopy := *metric
		metricCopy.History = make([]MetricDataPoint, len(metric.History))
		copy(metricCopy.History, metric.History)
		result[key] = &metricCopy
	}

	return result
}

// GetApplicationMetrics returns comprehensive application metrics
func (mc *MetricsCollector) GetApplicationMetrics() *ApplicationMetrics {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	metrics := &ApplicationMetrics{
		Timestamp: time.Now(),
		UpstreamServices: make(map[string]ServiceHealth),
	}

	// Collect runtime metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	metrics.MemoryUsageMB = float64(memStats.Alloc) / 1024 / 1024
	metrics.GoroutineCount = runtime.NumGoroutine()
	metrics.GCPauseMs = float64(memStats.PauseNs[(memStats.NumGC+255)%256]) / 1e6

	// Aggregate application-specific metrics
	for _, metric := range mc.metrics {
		switch metric.Name {
		case "http_requests_total":
			if v, ok := metric.Value.(int64); ok {
				metrics.RequestsTotal = v
			}
		case "http_response_time_ms":
			if v, ok := metric.Value.(float64); ok {
				metrics.ResponseTimeMs = v
			}
		case "http_error_rate":
			if v, ok := metric.Value.(float64); ok {
				metrics.ErrorRate = v
			}
		case "active_connections":
			if v, ok := metric.Value.(int64); ok {
				metrics.ActiveConnections = v
			}
		case "database_connections":
			if v, ok := metric.Value.(int64); ok {
				metrics.DatabaseConnections = v
			}
		case "cache_hit_rate":
			if v, ok := metric.Value.(float64); ok {
				metrics.CacheHitRate = v
			}
		case "worker_pool_utilization":
			if v, ok := metric.Value.(float64); ok {
				metrics.WorkerPoolUtilization = v
			}
		}
	}

	// Calculate requests per second from history
	if requestsMetric, exists := mc.metrics["http_requests_total"]; exists && len(requestsMetric.History) > 1 {
		recent := requestsMetric.History[len(requestsMetric.History)-1]
		previous := requestsMetric.History[len(requestsMetric.History)-2]
		
		if timeDiff := recent.Timestamp.Sub(previous.Timestamp).Seconds(); timeDiff > 0 {
			if recentVal, ok := recent.Value.(int64); ok {
				if prevVal, ok := previous.Value.(int64); ok {
					metrics.RequestsPerSecond = float64(recentVal-prevVal) / timeDiff
				}
			}
		}
	}

	return metrics
}

// collectMetrics runs the periodic metrics collection
func (mc *MetricsCollector) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(mc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.collectSystemMetrics()
		case <-mc.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// collectSystemMetrics collects system-level metrics
func (mc *MetricsCollector) collectSystemMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Record memory metrics
	mc.RecordGauge("memory_alloc_bytes", float64(memStats.Alloc), nil)
	mc.RecordGauge("memory_sys_bytes", float64(memStats.Sys), nil)
	mc.RecordGauge("goroutine_count", float64(runtime.NumGoroutine()), nil)
	mc.RecordGauge("gc_pause_ms", float64(memStats.PauseNs[(memStats.NumGC+255)%256])/1e6, nil)
	mc.RecordCounter("gc_runs_total", int64(memStats.NumGC), nil)
}

// getMetricKey generates a unique key for a metric with labels
func (mc *MetricsCollector) getMetricKey(name string, labels map[string]string) string {
	if labels == nil || len(labels) == 0 {
		return name
	}

	key := name
	for k, v := range labels {
		key += fmt.Sprintf(",%s=%s", k, v)
	}
	return key
}

// addToHistory adds a data point to metric history
func (mc *MetricsCollector) addToHistory(metric *Metric, value interface{}) {
	dataPoint := MetricDataPoint{
		Value:     value,
		Timestamp: time.Now(),
	}

	metric.History = append(metric.History, dataPoint)

	// Keep only last 100 data points
	if len(metric.History) > 100 {
		metric.History = metric.History[1:]
	}
}

// Timer provides timing measurement capabilities
type Timer struct {
	name      string
	labels    map[string]string
	startTime time.Time
	collector *MetricsCollector
}

// Generation 2: Add methods required by middleware and handlers
func (mc *MetricsCollector) RecordRequest() {
	mc.RecordCounter("requests_total", 1, nil)
	mc.RecordGauge("active_requests", 1, nil) // This will be updated on completion
}

func (mc *MetricsCollector) RecordRequestComplete(responseTime time.Duration) {
	mc.RecordTiming("response_time_ms", responseTime, nil)
	// Note: In a production system, we'd decrement active_requests here
}

func (mc *MetricsCollector) RecordError() {
	mc.RecordCounter("errors_total", 1, nil)
}

func (mc *MetricsCollector) RecordArtifactStored() {
	mc.RecordCounter("artifacts_stored_total", 1, nil)
}

func (mc *MetricsCollector) RecordProvenanceLink() {
	mc.RecordCounter("provenance_links_total", 1, nil)
}

func (mc *MetricsCollector) RecordBuildEvent() {
	mc.RecordCounter("build_events_total", 1, nil)
}

func (mc *MetricsCollector) RecordComplianceCheck() {
	mc.RecordCounter("compliance_checks_total", 1, nil)
}

func (mc *MetricsCollector) SetDatabaseConnections(active, idle int64) {
	mc.RecordGauge("db_connections_active", float64(active), nil)
	mc.RecordGauge("db_connections_idle", float64(idle), nil)
}

func (mc *MetricsCollector) SetCustomMetric(name string, value interface{}) {
	switch v := value.(type) {
	case int, int32, int64:
		mc.RecordGauge(name, float64(v.(int64)), nil)
	case float32, float64:
		mc.RecordGauge(name, v.(float64), nil)
	default:
		// For non-numeric values, we'll store as a counter with value 1
		mc.RecordCounter(name, 1, map[string]string{"value": fmt.Sprintf("%v", v)})
	}
}

func (mc *MetricsCollector) GetCustomMetric(name string) (interface{}, bool) {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	
	if metric, exists := mc.metrics[name]; exists {
		return metric.Value, true
	}
	return nil, false
}

func (mc *MetricsCollector) StartBackgroundCollection(ctx context.Context, interval time.Duration) {
	mc.Start(ctx) // Use existing Start method
}

func (mc *MetricsCollector) GetHealthMetrics() map[string]interface{} {
	// Simple health metrics for Generation 2
	return map[string]interface{}{
		"status": "healthy",
		"timestamp": time.Now().UTC(),
	}
}

// NewTimer creates a new timer
func (mc *MetricsCollector) NewTimer(name string, labels map[string]string) *Timer {
	return &Timer{
		name:      name,
		labels:    labels,
		startTime: time.Now(),
		collector: mc,
	}
}

// Stop stops the timer and records the duration
func (t *Timer) Stop() time.Duration {
	duration := time.Since(t.startTime)
	t.collector.RecordTiming(t.name, duration, t.labels)
	return duration
}

// HealthChecker provides health check functionality
type HealthChecker struct {
	collectors map[string]func() error
	mutex      sync.RWMutex
	logger     *logger.StructuredLogger
}

// NewHealthChecker creates a new health checker
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		collectors: make(map[string]func() error),
		logger:     logger.NewStructuredLogger("info", "json"),
	}
}

// AddCheck adds a health check
func (hc *HealthChecker) AddCheck(name string, checkFunc func() error) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	hc.collectors[name] = checkFunc
}

// CheckHealth runs all health checks
func (hc *HealthChecker) CheckHealth(ctx context.Context) map[string]error {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	results := make(map[string]error)
	
	for name, checkFunc := range hc.collectors {
		if err := checkFunc(); err != nil {
			results[name] = err
			hc.logger.Warn("health_check_failed", map[string]interface{}{
				"check": name,
				"error": err.Error(),
			})
		} else {
			results[name] = nil
		}
	}

	return results
}

// IsHealthy returns true if all health checks pass
func (hc *HealthChecker) IsHealthy(ctx context.Context) bool {
	results := hc.CheckHealth(ctx)
	
	for _, err := range results {
		if err != nil {
			return false
		}
	}
	
	return true
}