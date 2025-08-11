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
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/version"
)

func main() {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			Environment:  "development",
		},
		Security: config.SecurityConfig{
			CORSOrigins: []string{"*"},
		},
	}

	log.Printf("Starting Standalone Provenance Graph SBOM Linker v%s", version.Version)

	router := setupStandaloneRoutes(cfg)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		log.Printf("Server starting on port %d", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

func setupStandaloneRoutes(cfg *config.Config) *gin.Engine {
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS(cfg.Security.CORSOrigins))
	router.Use(middleware.Security())
	router.Use(middleware.RateLimiter())
	router.Use(middleware.RequestSizeLimit(10 * 1024 * 1024)) // 10MB limit

	// Health and observability endpoints (without database)
	healthHandler := handlers.NewHealthHandler(nil) // No database
	router.GET("/health", healthHandler.HealthCheck)
	router.GET("/health/ready", healthHandler.ReadinessCheck)
	router.GET("/health/live", healthHandler.LivenessCheck)
	router.GET("/metrics", healthHandler.MetricsHandler)

	api := router.Group("/api/v1")
	{
		api.GET("/version", handlers.NewVersionHandler().GetVersion)
		
		// Standalone artifact endpoints (in-memory storage for demo)
		artifacts := api.Group("/artifacts")
		{
			artifactHandler := handlers.NewStandaloneArtifactHandler()
			artifacts.POST("", artifactHandler.CreateArtifact)
			artifacts.GET("/:id", artifactHandler.GetArtifact)
			artifacts.GET("", artifactHandler.ListArtifacts)
		}

		// Standalone SBOM endpoints
		sbom := api.Group("/sbom")
		{
			sbomHandler := handlers.NewStandaloneSBOMHandler()
			sbom.POST("/generate", sbomHandler.GenerateSBOM)
			sbom.POST("/analyze", sbomHandler.AnalyzeSBOM)
		}

		// Compliance demo endpoints
		compliance := api.Group("/compliance")
		{
			complianceHandler := handlers.NewStandaloneComplianceHandler()
			compliance.GET("/nist-ssdf/status", complianceHandler.GetNISTSSDF)
			compliance.GET("/eu-cra/status", complianceHandler.GetEUCRA)
		}
	}

	return router
}