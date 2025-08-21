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
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/pipeline"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/cache"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/concurrency"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/autoscaling"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/loadbalancer"
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
	}).Info("Starting Self-Healing Provenance Graph SBOM Linker")

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
	
	// Initialize self-healing metrics
	selfHealingMetrics, err := monitoring.NewSelfHealingMetrics(logger)
	if err != nil {
		log.Fatalf("Failed to initialize self-healing metrics: %v", err)
	}
	
	// Initialize anomaly detector
	anomalyConfig := pipeline.DefaultAnomalyDetectionConfig()
	anomalyDetector := pipeline.NewAnomalyDetector(anomalyConfig, logger)
	err = anomalyDetector.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start anomaly detector: %v", err)
	}
	defer anomalyDetector.Stop()
	
	// Initialize intelligent auto-scaler
	scalingConfig := autoscaling.DefaultScalingConfig()
	intelligentScaler := autoscaling.NewIntelligentScaler(scalingConfig, metricsCollector, 5, logger)
	err = intelligentScaler.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start intelligent scaler: %v", err)
	}
	defer intelligentScaler.Stop()
	
	// Initialize self-healing pipeline
	selfHealingConfig := pipeline.DefaultSelfHealingConfig()
	pipelineStages := []pipeline.PipelineStage{
		pipeline.NewValidationStage(func(data interface{}) error {
			// Basic validation logic
			return nil
		}),
		pipeline.NewTransformationStage("sbom_processing", func(data interface{}) (interface{}, error) {
			// SBOM processing logic
			return data, nil
		}),
		pipeline.NewPersistenceStage(func(ctx context.Context, data interface{}) error {
			// Persistence logic
			return nil
		}),
	}
	
	pipelineConfig := pipeline.DefaultPipelineConfig()
	selfHealingPipeline := pipeline.NewSelfHealingPipeline(
		pipelineConfig,
		selfHealingConfig,
		pipelineStages,
		logger,
		metricsCollector,
	)
	
	err = selfHealingPipeline.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start self-healing pipeline: %v", err)
	}
	defer selfHealingPipeline.Stop(30 * time.Second)

	// Generation 3: Initialize performance optimization components
	performanceCache := cache.NewPerformanceCache(cache.CacheConfig{
		RedisAddress:        cfg.Redis.Host + ":" + fmt.Sprintf("%d", cfg.Redis.Port),
		RedisPassword:       cfg.Redis.Password,
		RedisDB:            cfg.Redis.DB,
		LocalCacheSize:     10000,
		DefaultTTL:         1 * time.Hour,
		PreloadingEnabled:  true,
		CompressionEnabled: true,
		HotKeyThreshold:    100,
		PartitionCount:     16,
		CleanupInterval:    5 * time.Minute,
		MaxMemoryMB:        512,
		PrefetchWorkers:    4,
		CompressionLevel:   6,
	}, metricsCollector)

	err = performanceCache.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start performance cache: %v", err)
	}
	defer performanceCache.Stop()

	resourcePool := concurrency.NewResourcePool(concurrency.PoolConfig{
		MinWorkers:             4,
		MaxWorkers:             50,
		InitialWorkers:         8,
		TaskQueueSize:          1000,
		ResultQueueSize:        500,
		WorkerTimeout:          5 * time.Minute,
		ScalingInterval:        30 * time.Second,
		CPUThreshold:           80.0,
		MemoryThreshold:        85.0,
		QueueThreshold:         0.8,
		AdaptiveScaling:        true,
		LoadBalancing:          true,
		ResourceMonitoring:     true,
		HealthCheckInterval:    30 * time.Second,
		GracefulShutdown:       30 * time.Second,
	}, metricsCollector)

	err = resourcePool.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start resource pool: %v", err)
	}
	defer resourcePool.Stop(ctx)

	loadBalancer := loadbalancer.NewIntelligentLoadBalancer(loadbalancer.LoadBalancerConfig{
		Algorithm:              loadbalancer.ResourceBasedAlgorithm,
		HealthCheckInterval:    30 * time.Second,
		HealthCheckTimeout:     5 * time.Second,
		HealthCheckPath:        "/health",
		MaxRetries:             3,
		RetryDelay:             1 * time.Second,
		CircuitBreakerConfig: loadbalancer.CircuitBreakerConfig{
			FailureThreshold:             5,
			RecoveryTimeout:              30 * time.Second,
			SuccessThreshold:             3,
			RequestVolumeThreshold:       20,
			ErrorPercentageThreshold:     50.0,
		},
		RateLimitConfig: loadbalancer.RateLimitConfig{
			RequestsPerSecond: 1000,
			BurstSize:         2000,
		},
		AutoScalingEnabled:      true,
		PredictiveScaling:       true,
		TrafficAnalysis:         true,
		SessionAffinity:         false,
		WeightedRouting:         true,
	}, metricsCollector)

	// Add local backend for load balancer testing
	err = loadBalancer.AddBackend(fmt.Sprintf("http://localhost:%d", cfg.Server.Port), 100, &loadbalancer.GeographicLocation{
		Region: "local",
		Zone:   "zone-1",
	})
	if err != nil {
		log.Printf("Warning: Failed to add backend to load balancer: %v", err)
	}

	err = loadBalancer.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start load balancer: %v", err)
	}
	defer loadBalancer.Stop()

	logger.Info("Generation 3 performance optimization components initialized", logrus.Fields{
		"performance_cache": "enabled",
		"resource_pool":     "enabled", 
		"load_balancer":     "enabled",
	})
	
	// Start monitoring integration
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				// Feed metrics to anomaly detector
				appMetrics := metricsCollector.GetApplicationMetrics()
				anomalyDetector.AddDataPoint("cpu_utilization", appMetrics.CPUUsagePercent, nil)
				anomalyDetector.AddDataPoint("memory_usage_mb", appMetrics.MemoryUsageMB, nil)
				anomalyDetector.AddDataPoint("response_time_ms", appMetrics.ResponseTimeMs, nil)
				anomalyDetector.AddDataPoint("error_rate", appMetrics.ErrorRate, nil)
				
				// Record self-healing metrics
				componentHealth := selfHealingPipeline.GetComponentHealth()
				for componentID, health := range componentHealth {
					healthStatus := 0
					switch health.Status.String() {
					case "HEALTHY":
						healthStatus = 0
					case "DEGRADED":
						healthStatus = 1
					case "UNHEALTHY":
						healthStatus = 2
					case "CRITICAL":
						healthStatus = 3
					}
					
					selfHealingMetrics.UpdateComponentHealth(
						ctx,
						componentID,
						healthStatus,
						health.ErrorRate,
						float64(health.Latency.Milliseconds()),
					)
				}
				
			case <-ctx.Done():
				return
			}
		}
	}()

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

	logger.Info("Self-healing provenance server exited gracefully")
}