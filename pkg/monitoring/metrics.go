package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type Metrics struct {
	meter              metric.Meter
	tracer             oteltrace.Tracer
	
	artifactsTotal     metric.Int64Counter
	verificationsTotal metric.Int64Counter
	sbomVulns         metric.Int64Histogram
	complianceScore   metric.Float64Gauge
	graphNodes        metric.Int64Counter
	signatureValidations metric.Int64Counter
	requestDuration   metric.Float64Histogram
	requestsTotal     metric.Int64Counter
	errorsTotal       metric.Int64Counter
	cacheHits         metric.Int64Counter
	cacheMisses       metric.Int64Counter
	
	mu            sync.RWMutex
	customMetrics map[string]interface{}
}

type MetricsConfig struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	OTLPEndpoint   string
	Headers        map[string]string
	EnableTracing  bool
	EnableMetrics  bool
}

func NewMetrics(config *MetricsConfig) (*Metrics, error) {
	ctx := context.Background()

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(config.ServiceName),
			semconv.ServiceVersionKey.String(config.ServiceVersion),
			semconv.DeploymentEnvironmentKey.String(config.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	var traceProvider *trace.TracerProvider
	if config.EnableTracing && config.OTLPEndpoint != "" {
		traceExporter, err := otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint(config.OTLPEndpoint),
			otlptracehttp.WithHeaders(config.Headers),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create trace exporter: %w", err)
		}

		traceProvider = trace.NewTracerProvider(
			trace.WithBatcher(traceExporter),
			trace.WithResource(res),
		)
		otel.SetTracerProvider(traceProvider)
	}

	var meterProvider *metric.MeterProvider
	if config.EnableMetrics {
		meterProvider = metric.NewMeterProvider(
			metric.WithResource(res),
		)
		otel.SetMeterProvider(meterProvider)
	}

	meter := otel.Meter("provenance-linker")
	tracer := otel.Tracer("provenance-linker")

	m := &Metrics{
		meter:         meter,
		tracer:        tracer,
		customMetrics: make(map[string]interface{}),
	}

	if err := m.initializeMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	return m, nil
}

func (m *Metrics) initializeMetrics() error {
	var err error

	m.artifactsTotal, err = m.meter.Int64Counter(
		"provenance_artifacts_total",
		metric.WithDescription("Total number of artifacts tracked"),
	)
	if err != nil {
		return err
	}

	m.verificationsTotal, err = m.meter.Int64Counter(
		"provenance_verifications_total",
		metric.WithDescription("Total number of verifications performed"),
	)
	if err != nil {
		return err
	}

	m.sbomVulns, err = m.meter.Int64Histogram(
		"provenance_sbom_vulnerabilities",
		metric.WithDescription("Number of vulnerabilities found in SBOMs"),
	)
	if err != nil {
		return err
	}

	m.complianceScore, err = m.meter.Float64Gauge(
		"provenance_compliance_score",
		metric.WithDescription("Compliance score for various standards"),
	)
	if err != nil {
		return err
	}

	m.graphNodes, err = m.meter.Int64Counter(
		"provenance_graph_nodes_total",
		metric.WithDescription("Total number of nodes in provenance graphs"),
	)
	if err != nil {
		return err
	}

	m.signatureValidations, err = m.meter.Int64Counter(
		"provenance_signature_validations",
		metric.WithDescription("Number of signature validations performed"),
	)
	if err != nil {
		return err
	}

	m.requestDuration, err = m.meter.Float64Histogram(
		"http_request_duration_seconds",
		metric.WithDescription("HTTP request duration in seconds"),
	)
	if err != nil {
		return err
	}

	m.requestsTotal, err = m.meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
	)
	if err != nil {
		return err
	}

	m.errorsTotal, err = m.meter.Int64Counter(
		"provenance_errors_total",
		metric.WithDescription("Total number of errors"),
	)
	if err != nil {
		return err
	}

	m.cacheHits, err = m.meter.Int64Counter(
		"cache_hits_total",
		metric.WithDescription("Total number of cache hits"),
	)
	if err != nil {
		return err
	}

	m.cacheMisses, err = m.meter.Int64Counter(
		"cache_misses_total",
		metric.WithDescription("Total number of cache misses"),
	)
	if err != nil {
		return err
	}

	return nil
}

func (m *Metrics) RecordArtifact(ctx context.Context, artifactType string) {
	m.artifactsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", artifactType),
	))
}

func (m *Metrics) RecordVerification(ctx context.Context, result string, method string) {
	m.verificationsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", result),
		attribute.String("method", method),
	))
}

func (m *Metrics) RecordSBOMVulnerabilities(ctx context.Context, count int64, severity string) {
	m.sbomVulns.Record(ctx, count, metric.WithAttributes(
		attribute.String("severity", severity),
	))
}

func (m *Metrics) SetComplianceScore(ctx context.Context, standard string, score float64) {
	m.complianceScore.Record(ctx, score, metric.WithAttributes(
		attribute.String("standard", standard),
	))
}

func (m *Metrics) RecordGraphNodes(ctx context.Context, nodeType string, count int64) {
	m.graphNodes.Add(ctx, count, metric.WithAttributes(
		attribute.String("type", nodeType),
	))
}

func (m *Metrics) RecordSignatureValidation(ctx context.Context, algorithm string, result string) {
	m.signatureValidations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("algorithm", algorithm),
		attribute.String("result", result),
	))
}

func (m *Metrics) RecordHTTPRequest(ctx context.Context, method, path string, statusCode int, duration time.Duration) {
	attrs := []attribute.KeyValue{
		attribute.String("method", method),
		attribute.String("path", path),
		attribute.Int("status_code", statusCode),
	}

	m.requestsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
}

func (m *Metrics) RecordError(ctx context.Context, errorType, component string) {
	m.errorsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", errorType),
		attribute.String("component", component),
	))
}

func (m *Metrics) RecordCacheHit(ctx context.Context, cacheType string) {
	m.cacheHits.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", cacheType),
	))
}

func (m *Metrics) RecordCacheMiss(ctx context.Context, cacheType string) {
	m.cacheMisses.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", cacheType),
	))
}

func (m *Metrics) StartTrace(ctx context.Context, name string) (context.Context, oteltrace.Span) {
	return m.tracer.Start(ctx, name)
}

func (m *Metrics) AddSpanEvent(span oteltrace.Span, name string, attrs ...attribute.KeyValue) {
	span.AddEvent(name, oteltrace.WithAttributes(attrs...))
}

func (m *Metrics) SetSpanStatus(span oteltrace.Span, code oteltrace.StatusCode, description string) {
	span.SetStatus(code, description)
}

func (m *Metrics) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			ctx, span := m.StartTrace(r.Context(), fmt.Sprintf("%s %s", r.Method, r.URL.Path))
			defer span.End()

			span.SetAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.url", r.URL.String()),
				attribute.String("http.scheme", r.URL.Scheme),
				attribute.String("http.host", r.Host),
				attribute.String("http.user_agent", r.UserAgent()),
			)

			rr := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
			
			next.ServeHTTP(rr, r.WithContext(ctx))
			
			duration := time.Since(start)
			
			span.SetAttributes(
				attribute.Int("http.status_code", rr.statusCode),
				attribute.String("http.status_text", http.StatusText(rr.statusCode)),
			)

			if rr.statusCode >= 400 {
				span.SetStatus(oteltrace.StatusCodeError, http.StatusText(rr.statusCode))
				m.RecordError(ctx, "http_error", "api")
			}

			m.RecordHTTPRequest(ctx, r.Method, r.URL.Path, rr.statusCode, duration)
		})
	}
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

func (m *Metrics) HealthCheck(ctx context.Context) error {
	_, span := m.StartTrace(ctx, "health_check")
	defer span.End()

	span.AddEvent("health check performed")
	return nil
}

type PerformanceMonitor struct {
	metrics *Metrics
	mu      sync.RWMutex
	stats   map[string]*PerformanceStats
}

type PerformanceStats struct {
	Count       int64
	TotalTime   time.Duration
	AverageTime time.Duration
	MinTime     time.Duration
	MaxTime     time.Duration
}

func NewPerformanceMonitor(metrics *Metrics) *PerformanceMonitor {
	return &PerformanceMonitor{
		metrics: metrics,
		stats:   make(map[string]*PerformanceStats),
	}
}

func (pm *PerformanceMonitor) Track(operation string) func() {
	start := time.Now()
	return func() {
		duration := time.Since(start)
		pm.recordOperation(operation, duration)
	}
}

func (pm *PerformanceMonitor) recordOperation(operation string, duration time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	stats, exists := pm.stats[operation]
	if !exists {
		stats = &PerformanceStats{
			MinTime: duration,
			MaxTime: duration,
		}
		pm.stats[operation] = stats
	}

	stats.Count++
	stats.TotalTime += duration
	stats.AverageTime = stats.TotalTime / time.Duration(stats.Count)

	if duration < stats.MinTime {
		stats.MinTime = duration
	}
	if duration > stats.MaxTime {
		stats.MaxTime = duration
	}
}

func (pm *PerformanceMonitor) GetStats(operation string) *PerformanceStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats, exists := pm.stats[operation]
	if !exists {
		return nil
	}

	return &PerformanceStats{
		Count:       stats.Count,
		TotalTime:   stats.TotalTime,
		AverageTime: stats.AverageTime,
		MinTime:     stats.MinTime,
		MaxTime:     stats.MaxTime,
	}
}

func (pm *PerformanceMonitor) GetAllStats() map[string]*PerformanceStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make(map[string]*PerformanceStats)
	for operation, stats := range pm.stats {
		result[operation] = &PerformanceStats{
			Count:       stats.Count,
			TotalTime:   stats.TotalTime,
			AverageTime: stats.AverageTime,
			MinTime:     stats.MinTime,
			MaxTime:     stats.MaxTime,
		}
	}

	return result
}