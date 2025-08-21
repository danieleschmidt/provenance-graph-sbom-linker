package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
)

// MetricsMiddleware provides request metrics collection
type MetricsMiddleware struct {
	collector *monitoring.MetricsCollector
}

// NewMetricsMiddleware creates a new metrics middleware
func NewMetricsMiddleware(collector *monitoring.MetricsCollector) *MetricsMiddleware {
	return &MetricsMiddleware{
		collector: collector,
	}
}

// CollectMetrics middleware function that collects request metrics
func (mm *MetricsMiddleware) CollectMetrics() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		
		// Record request start
		mm.collector.RecordRequest()
		
		// Process request
		c.Next()
		
		// Calculate response time
		responseTime := time.Since(start)
		
		// Record request completion
		mm.collector.RecordRequestComplete(responseTime)
		
		// Record errors if status code indicates error
		if c.Writer.Status() >= 400 {
			mm.collector.RecordError()
		}
		
		// Set response headers for observability
		c.Header("X-Response-Time", responseTime.String())
		c.Header("X-Request-ID", c.GetString("request_id"))
	})
}

// generateRequestID generates a simple request ID (internal function)
func generateRequestID() string {
	// Simple timestamp-based ID for Generation 2
	// Will be enhanced with proper UUID in Generation 3
	return time.Now().Format("20060102150405.000000")
}

// HealthCheck provides middleware-level health checking
func (mm *MetricsMiddleware) HealthCheck() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		healthMetrics := mm.collector.GetHealthMetrics()
		
		// Add health status to context for other middleware/handlers
		c.Set("health_status", healthMetrics["status"])
		c.Set("health_metrics", healthMetrics)
		
		c.Next()
	})
}