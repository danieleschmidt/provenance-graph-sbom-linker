package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/database"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/version"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
)

type HealthHandler struct {
	db     *database.Neo4jDB
	logger *logger.StructuredLogger
}

func NewHealthHandler(db *database.Neo4jDB) *HealthHandler {
	return &HealthHandler{
		db:     db,
		logger: logger.NewStructuredLogger("info", "json"),
	}
}

type HealthCheck struct {
	Status      string                 `json:"status"`
	Version     string                 `json:"version"`
	Timestamp   time.Time              `json:"timestamp"`
	Uptime      string                 `json:"uptime"`
	Checks      map[string]interface{} `json:"checks"`
	Metadata    map[string]interface{} `json:"metadata"`
	Environment string                 `json:"environment"`
}

var startTime = time.Now()

func (h *HealthHandler) HealthCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	checks := make(map[string]interface{})
	overallStatus := "healthy"

	// Database connectivity check
	if dbCheck := h.checkDatabase(ctx); dbCheck != nil {
		checks["database"] = dbCheck
		if status, ok := dbCheck["status"].(string); ok && status != "healthy" {
			overallStatus = "unhealthy"
		}
	}

	// Memory check
	checks["memory"] = h.checkMemory()

	// Disk space check
	checks["disk"] = h.checkDisk()

	// Service dependencies check
	checks["dependencies"] = h.checkDependencies(ctx)

	healthCheck := HealthCheck{
		Status:      overallStatus,
		Version:     version.Version,
		Timestamp:   time.Now().UTC(),
		Uptime:      time.Since(startTime).String(),
		Checks:      checks,
		Environment: "production", // TODO: Get from config
		Metadata: map[string]interface{}{
			"service":   "provenance-linker",
			"component": "health-check",
			"hostname":  "localhost", // TODO: Get actual hostname
		},
	}

	// Log health check
	h.logger.Info("Health check completed", map[string]interface{}{
		"status":    overallStatus,
		"checks":    len(checks),
		"operation": "health_check",
	})

	statusCode := http.StatusOK
	if overallStatus != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, healthCheck)
}

func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ready := true
	checks := make(map[string]interface{})

	// Check critical dependencies
	if dbCheck := h.checkDatabase(ctx); dbCheck != nil {
		checks["database"] = dbCheck
		if status, ok := dbCheck["status"].(string); ok && status != "healthy" {
			ready = false
		}
	} else {
		ready = false
	}

	status := "ready"
	statusCode := http.StatusOK
	if !ready {
		status = "not_ready"
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, gin.H{
		"status":    status,
		"timestamp": time.Now().UTC(),
		"checks":    checks,
	})
}

func (h *HealthHandler) LivenessCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "alive",
		"timestamp": time.Now().UTC(),
		"uptime":    time.Since(startTime).String(),
		"version":   version.Version,
	})
}

func (h *HealthHandler) checkDatabase(ctx context.Context) map[string]interface{} {
	start := time.Now()
	result := make(map[string]interface{})
	
	if h.db == nil {
		result["status"] = "unhealthy"
		result["error"] = "database not configured"
		return result
	}

	// Simple connectivity test
	session := h.db.GetSession()
	if session == nil {
		result["status"] = "unhealthy"
		result["error"] = "failed to get database session"
		return result
	}
	defer session.Close(ctx)

	// Try to execute a simple query
	_, err := session.Run(ctx, "RETURN 1 as test", nil)
	if err != nil {
		result["status"] = "unhealthy"
		result["error"] = err.Error()
		result["response_time_ms"] = time.Since(start).Milliseconds()
		return result
	}

	result["status"] = "healthy"
	result["response_time_ms"] = time.Since(start).Milliseconds()
	result["connection_active"] = true
	
	return result
}

func (h *HealthHandler) checkMemory() map[string]interface{} {
	// Simple memory check - in production use runtime.MemStats
	return map[string]interface{}{
		"status":      "healthy",
		"usage_bytes": 1024 * 1024 * 64, // Placeholder
		"limit_bytes": 1024 * 1024 * 512,
	}
}

func (h *HealthHandler) checkDisk() map[string]interface{} {
	// Simple disk check - in production use syscall.Statfs
	return map[string]interface{}{
		"status":           "healthy",
		"available_bytes":  1024 * 1024 * 1024 * 10, // 10GB
		"total_bytes":      1024 * 1024 * 1024 * 50, // 50GB
		"usage_percentage": 20.0,
	}
}

func (h *HealthHandler) checkDependencies(ctx context.Context) map[string]interface{} {
	dependencies := make(map[string]interface{})
	
	// Check external services
	dependencies["redis"] = map[string]interface{}{
		"status":  "healthy", // Placeholder
		"latency": "5ms",
	}
	
	dependencies["observability"] = map[string]interface{}{
		"status":  "healthy", // Placeholder
		"metrics": "available",
	}
	
	return dependencies
}

func (h *HealthHandler) MetricsHandler(c *gin.Context) {
	metrics := map[string]interface{}{
		"timestamp":        time.Now().UTC(),
		"uptime_seconds":   time.Since(startTime).Seconds(),
		"total_requests":   12345, // TODO: Implement actual metrics
		"active_sessions":  42,
		"artifacts_stored": 1000,
		"provenance_links": 5000,
		"build_events":     250,
		"compliance_checks": 50,
		"performance": map[string]interface{}{
			"avg_response_time_ms":  125.5,
			"p95_response_time_ms":  250.0,
			"p99_response_time_ms":  500.0,
			"error_rate_percent":    0.5,
		},
		"database": map[string]interface{}{
			"connections_active": 10,
			"connections_idle":   5,
			"query_time_avg_ms":  45.2,
		},
	}

	c.JSON(http.StatusOK, metrics)
}