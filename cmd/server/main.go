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

	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/api"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/config"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/database"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/version"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/monitoring"
	pkgErrors "github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/errors"
	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize structured logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.JSONFormatter{})
	
	// Initialize error reporter and recovery handler
	errorReporter := pkgErrors.NewErrorReporter(logger)
	recoveryHandler := pkgErrors.NewRecoveryHandler(logger)
	
	// Initialize metrics collector
	metricsCollector := monitoring.NewMetricsCollector()
	
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger.WithFields(logrus.Fields{
		"version": version.Version,
		"commit":  version.Commit,
		"date":    version.Date,
	}).Info("Starting Provenance Graph SBOM Linker")

	// Start background metrics collection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metricsCollector.StartBackgroundCollection(ctx, time.Minute)

	db, err := database.NewNeo4jConnection(cfg.Database)
	if err != nil {
		errorReporter.ReportCriticalError(ctx, err, "database_connection", map[string]interface{}{
			"component": "neo4j",
		})
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	router := api.SetupRoutes(db, cfg, metricsCollector, recoveryHandler)

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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}