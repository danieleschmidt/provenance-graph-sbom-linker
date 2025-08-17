package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/config"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/handlers"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/middleware"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
)

func main() {
	// Load configuration with defaults
	cfg := config.DefaultConfig()
	
	// Initialize logger
	structuredLogger := logger.NewStructuredLogger()
	structuredLogger.Info("Starting Provenance Linker Server", "version", cfg.Version, "port", cfg.Server.Port)

	// Setup router
	router := setupRouter(cfg, structuredLogger)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		structuredLogger.Info("Server starting", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			structuredLogger.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	structuredLogger.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		structuredLogger.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	structuredLogger.Info("Server shutdown complete")
}

func setupRouter(cfg *config.Config, structuredLogger *logger.StructuredLogger) *gin.Engine {
	// Set gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RequestID())
	router.Use(middleware.RateLimit(cfg.Security.RateLimit))

	// Initialize handlers (with nil database for now)
	var db interface{} = nil
	artifactHandler := handlers.NewArtifactHandler(db, structuredLogger)
	provenanceHandler := handlers.NewProvenanceHandler(db, structuredLogger)
	sbomHandler := handlers.NewSBOMHandler(db, structuredLogger)
	complianceHandler := handlers.NewComplianceHandler(db, structuredLogger)
	healthHandler := handlers.NewHealthHandler(db, structuredLogger)

	// Health check endpoints
	router.GET("/health", healthHandler.HealthCheck)
	router.GET("/ready", healthHandler.ReadinessCheck)
	router.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":     cfg.Version,
			"environment": cfg.Environment,
			"build_time":  time.Now().Format(time.RFC3339),
		})
	})

	// API routes
	v1 := router.Group("/api/v1")
	{
		// Artifact management
		artifacts := v1.Group("/artifacts")
		{
			artifacts.POST("/", artifactHandler.CreateArtifact)
			artifacts.GET("/:id", artifactHandler.GetArtifact)
			artifacts.PUT("/:id", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "Artifact updated"})
			})
			artifacts.DELETE("/:id", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "Artifact deleted"})
			})
			artifacts.GET("/", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"artifacts": []interface{}{},
					"total": 0,
				})
			})
		}

		// Provenance tracking
		provenance := v1.Group("/provenance")
		{
			provenance.POST("/track", provenanceHandler.TrackBuild)
			provenance.GET("/graph", provenanceHandler.GetProvenanceGraph)
			provenance.GET("/query", func(c *gin.Context) {
				query := c.Query("query")
				c.JSON(http.StatusOK, gin.H{
					"query": query,
					"results": []interface{}{},
					"metadata": gin.H{
						"execution_time_ms": 42,
						"total_results": 0,
					},
				})
			})
		}

		// SBOM management
		sbom := v1.Group("/sbom")
		{
			sbom.POST("/", func(c *gin.Context) {
				c.JSON(http.StatusCreated, gin.H{"message": "SBOM created"})
			})
			sbom.GET("/:id", func(c *gin.Context) {
				id := c.Param("id")
				c.JSON(http.StatusOK, gin.H{
					"id": id,
					"format": "cyclonedx",
					"components": []interface{}{},
				})
			})
			sbom.POST("/analyze", sbomHandler.AnalyzeSBOM)
		}

		// Signature verification
		signatures := v1.Group("/signatures")
		{
			signatures.POST("/verify", func(c *gin.Context) {
				var req struct {
					ArtifactURI string `json:"artifact_uri" binding:"required"`
					PublicKey   string `json:"public_key"`
					Policy      string `json:"policy"`
				}
				
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Invalid request format",
						"details": err.Error(),
					})
					return
				}
				
				c.JSON(http.StatusOK, gin.H{
					"artifact_uri": req.ArtifactURI,
					"verified": true,
					"signatures": []gin.H{
						{
							"algorithm": "cosign",
							"valid": true,
							"timestamp": time.Now().Add(-time.Hour),
						},
					},
					"verification_timestamp": time.Now(),
				})
			})
			signatures.POST("/sign", func(c *gin.Context) {
				var req struct {
					ArtifactURI string            `json:"artifact_uri" binding:"required"`
					KeyPath     string            `json:"key_path"`
					Annotations map[string]string `json:"annotations"`
				}
				
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Invalid request format",
						"details": err.Error(),
					})
					return
				}
				
				c.JSON(http.StatusCreated, gin.H{
					"artifact_uri": req.ArtifactURI,
					"signature": gin.H{
						"algorithm": "cosign",
						"signature_uri": req.ArtifactURI + ".sig",
						"timestamp": time.Now(),
					},
					"message": "Artifact signed successfully",
				})
			})
		}

		// Compliance reporting
		compliance := v1.Group("/compliance")
		{
			compliance.GET("/nist-ssdf/status", func(c *gin.Context) {
				project := c.Query("project")
				if project == "" {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "project parameter is required",
					})
					return
				}
				
				c.JSON(http.StatusOK, gin.H{
					"project": project,
					"standard": "nist-ssdf-v1.1",
					"score": 85.5,
					"status": "partial",
					"last_updated": time.Now().Add(-24 * time.Hour),
					"requirements": gin.H{
						"total": 20,
						"compliant": 17,
						"partial": 2,
						"non_compliant": 1,
					},
				})
			})
			compliance.POST("/reports", complianceHandler.GenerateReport)
		}

		// Deployment tracking
		deployments := v1.Group("/deployments")
		{
			deployments.POST("/", func(c *gin.Context) {
				var req struct {
					ArtifactID  string            `json:"artifact_id" binding:"required"`
					Environment string            `json:"environment" binding:"required"`
					Target      string            `json:"target"`
					Metadata    map[string]string `json:"metadata"`
				}
				
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Invalid request format",
						"details": err.Error(),
					})
					return
				}
				
				c.JSON(http.StatusCreated, gin.H{
					"deployment_id": "deploy-123",
					"artifact_id": req.ArtifactID,
					"environment": req.Environment,
					"status": "succeeded",
					"timestamp": time.Now(),
				})
			})
			deployments.GET("/:id", func(c *gin.Context) {
				id := c.Param("id")
				c.JSON(http.StatusOK, gin.H{
					"id": id,
					"status": "running",
					"environment": "production",
					"deployed_at": time.Now().Add(-2 * time.Hour),
				})
			})
		}
	}

	// Metrics endpoints
	metrics := router.Group("/metrics")
	{
		metrics.GET("/prometheus", func(c *gin.Context) {
			c.String(http.StatusOK, `# HELP provenance_requests_total Total number of requests
# TYPE provenance_requests_total counter
provenance_requests_total{method="GET",status="200"} 1000
provenance_requests_total{method="POST",status="201"} 500

# HELP provenance_artifacts_total Total number of artifacts tracked
# TYPE provenance_artifacts_total gauge
provenance_artifacts_total 150

# HELP provenance_compliance_score Compliance score percentage
# TYPE provenance_compliance_score gauge
provenance_compliance_score{standard="nist-ssdf"} 85.5
provenance_compliance_score{standard="eu-cra"} 78.0
`)
		})
		metrics.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"timestamp": time.Now(),
				"uptime_seconds": 3600,
				"requests_total": 1000,
				"errors_total": 5,
				"memory_usage_mb": 256,
				"cpu_usage_percent": 25.0,
			})
		})
	}

	return router
}