package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// TelemetryManager handles all observability concerns
type TelemetryManager struct {
	tracer  trace.Tracer
	meter   metric.Meter
	metrics *Metrics
}

// Metrics holds all application metrics
type Metrics struct {
	// HTTP metrics
	RequestCount    metric.Int64Counter
	RequestDuration metric.Float64Histogram
	RequestSize     metric.Int64Histogram
	ResponseSize    metric.Int64Histogram

	// Database metrics
	DBConnections    metric.Int64UpDownCounter
	DBQueryDuration  metric.Float64Histogram
	DBQueryCount     metric.Int64Counter

	// Business metrics
	ArtifactsProcessed    metric.Int64Counter
	SBOMsGenerated       metric.Int64Counter
	SignaturesVerified   metric.Int64Counter
	ComplianceChecks     metric.Int64Counter

	// System metrics
	MemoryUsage     metric.Int64UpDownCounter
	GoroutineCount  metric.Int64UpDownCounter
	CPUUsage        metric.Float64UpDownCounter
}

// NewTelemetryManager creates a new telemetry manager
func NewTelemetryManager(serviceName, version string) (*TelemetryManager, error) {
	tracer := otel.Tracer(serviceName)
	meter := otel.Meter(serviceName)

	metrics, err := initializeMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	tm := &TelemetryManager{
		tracer:  tracer,
		meter:   meter,
		metrics: metrics,
	}

	// Start background metrics collection
	go tm.collectSystemMetrics()

	return tm, nil
}

// initializeMetrics sets up all application metrics
func initializeMetrics(meter metric.Meter) (*Metrics, error) {
	requestCount, err := meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
	)
	if err != nil {
		return nil, err
	}

	requestDuration, err := meter.Float64Histogram(
		"http_request_duration_seconds",
		metric.WithDescription("HTTP request duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	requestSize, err := meter.Int64Histogram(
		"http_request_size_bytes",
		metric.WithDescription("HTTP request size in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, err
	}

	responseSize, err := meter.Int64Histogram(
		"http_response_size_bytes",
		metric.WithDescription("HTTP response size in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, err
	}

	dbConnections, err := meter.Int64UpDownCounter(
		"database_connections_active",
		metric.WithDescription("Number of active database connections"),
	)
	if err != nil {
		return nil, err
	}

	dbQueryDuration, err := meter.Float64Histogram(
		"database_query_duration_seconds",
		metric.WithDescription("Database query duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	dbQueryCount, err := meter.Int64Counter(
		"database_queries_total",
		metric.WithDescription("Total number of database queries"),
	)
	if err != nil {
		return nil, err
	}

	artifactsProcessed, err := meter.Int64Counter(
		"artifacts_processed_total",
		metric.WithDescription("Total number of artifacts processed"),
	)
	if err != nil {
		return nil, err
	}

	sbomsGenerated, err := meter.Int64Counter(
		"sboms_generated_total",
		metric.WithDescription("Total number of SBOMs generated"),
	)
	if err != nil {
		return nil, err
	}

	signaturesVerified, err := meter.Int64Counter(
		"signatures_verified_total",
		metric.WithDescription("Total number of signatures verified"),
	)
	if err != nil {
		return nil, err
	}

	complianceChecks, err := meter.Int64Counter(
		"compliance_checks_total",
		metric.WithDescription("Total number of compliance checks performed"),
	)
	if err != nil {
		return nil, err
	}

	memoryUsage, err := meter.Int64UpDownCounter(
		"memory_usage_bytes",
		metric.WithDescription("Current memory usage in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, err
	}

	goroutineCount, err := meter.Int64UpDownCounter(
		"goroutines_active",
		metric.WithDescription("Number of active goroutines"),
	)
	if err != nil {
		return nil, err
	}

	cpuUsage, err := meter.Float64UpDownCounter(
		"cpu_usage_percent",
		metric.WithDescription("CPU usage percentage"),
		metric.WithUnit("%"),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		RequestCount:         requestCount,
		RequestDuration:      requestDuration,
		RequestSize:          requestSize,
		ResponseSize:         responseSize,
		DBConnections:        dbConnections,
		DBQueryDuration:      dbQueryDuration,
		DBQueryCount:         dbQueryCount,
		ArtifactsProcessed:   artifactsProcessed,
		SBOMsGenerated:       sbomsGenerated,
		SignaturesVerified:   signaturesVerified,
		ComplianceChecks:     complianceChecks,
		MemoryUsage:          memoryUsage,
		GoroutineCount:       goroutineCount,
		CPUUsage:             cpuUsage,
	}, nil
}

// TraceHTTPRequest creates a span for HTTP requests
func (tm *TelemetryManager) TraceHTTPRequest(ctx context.Context, method, path string) (context.Context, trace.Span) {
	return tm.tracer.Start(ctx, fmt.Sprintf("%s %s", method, path),
		trace.WithAttributes(
			attribute.String("http.method", method),
			attribute.String("http.route", path),
		),
	)
}

// RecordHTTPMetrics records HTTP-related metrics
func (tm *TelemetryManager) RecordHTTPMetrics(ctx context.Context, method, path, status string, duration time.Duration, requestSize, responseSize int64) {
	attrs := []attribute.KeyValue{
		attribute.String("method", method),
		attribute.String("path", path),
		attribute.String("status", status),
	}

	tm.metrics.RequestCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	tm.metrics.RequestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
	tm.metrics.RequestSize.Record(ctx, requestSize, metric.WithAttributes(attrs...))
	tm.metrics.ResponseSize.Record(ctx, responseSize, metric.WithAttributes(attrs...))
}

// RecordDatabaseMetrics records database-related metrics
func (tm *TelemetryManager) RecordDatabaseMetrics(ctx context.Context, operation string, duration time.Duration, success bool) {
	attrs := []attribute.KeyValue{
		attribute.String("operation", operation),
		attribute.Bool("success", success),
	}

	tm.metrics.DBQueryCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	tm.metrics.DBQueryDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
}

// RecordBusinessMetrics records business logic metrics
func (tm *TelemetryManager) RecordBusinessMetrics(ctx context.Context, metricType string, value int64, attributes ...attribute.KeyValue) {
	switch metricType {
	case "artifacts_processed":
		tm.metrics.ArtifactsProcessed.Add(ctx, value, metric.WithAttributes(attributes...))
	case "sboms_generated":
		tm.metrics.SBOMsGenerated.Add(ctx, value, metric.WithAttributes(attributes...))
	case "signatures_verified":
		tm.metrics.SignaturesVerified.Add(ctx, value, metric.WithAttributes(attributes...))
	case "compliance_checks":
		tm.metrics.ComplianceChecks.Add(ctx, value, metric.WithAttributes(attributes...))
	}
}

// collectSystemMetrics collects system-level metrics periodically
func (tm *TelemetryManager) collectSystemMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()

		// Memory metrics
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		tm.metrics.MemoryUsage.Add(ctx, int64(m.Alloc))

		// Goroutine count
		tm.metrics.GoroutineCount.Add(ctx, int64(runtime.NumGoroutine()))

		// CPU usage would require more sophisticated collection
		// For now, we'll use a placeholder
		tm.metrics.CPUUsage.Add(ctx, 0.0)
	}
}

// HTTPMiddleware provides telemetry for HTTP handlers
func (tm *TelemetryManager) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// Start trace
			ctx, span := tm.TraceHTTPRequest(r.Context(), r.Method, r.URL.Path)
			r = r.WithContext(ctx)
			defer span.End()

			// Wrap response writer to capture metrics
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Call next handler
			next.ServeHTTP(wrapped, r)

			// Record metrics
			duration := time.Since(start)
			tm.RecordHTTPMetrics(
				ctx,
				r.Method,
				r.URL.Path,
				fmt.Sprintf("%d", wrapped.statusCode),
				duration,
				r.ContentLength,
				wrapped.responseSize,
			)

			// Add span attributes
			span.SetAttributes(
				attribute.String("http.status_code", fmt.Sprintf("%d", wrapped.statusCode)),
				attribute.Int64("http.request_size", r.ContentLength),
				attribute.Int64("http.response_size", wrapped.responseSize),
				attribute.Float64("http.duration_seconds", duration.Seconds()),
			)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture metrics
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	responseSize int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.responseSize += int64(size)
	return size, err
}

// DatabaseTracingWrapper provides database operation tracing
func (tm *TelemetryManager) DatabaseTracingWrapper(operation string, fn func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		start := time.Now()
		
		// Start trace
		ctx, span := tm.tracer.Start(ctx, fmt.Sprintf("db.%s", operation),
			trace.WithAttributes(
				attribute.String("db.operation", operation),
			),
		)
		defer span.End()

		// Execute operation
		err := fn(ctx)
		
		// Record metrics
		duration := time.Since(start)
		tm.RecordDatabaseMetrics(ctx, operation, duration, err == nil)

		// Add span attributes
		span.SetAttributes(
			attribute.Bool("db.success", err == nil),
			attribute.Float64("db.duration_seconds", duration.Seconds()),
		)

		if err != nil {
			span.SetAttributes(attribute.String("db.error", err.Error()))
		}

		return err
	}
}