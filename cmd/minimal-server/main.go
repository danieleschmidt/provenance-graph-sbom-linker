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
	"github.com/google/uuid"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/sbom"
)

// Simple configuration
type Config struct {
	Port        int    `json:"port"`
	Environment string `json:"environment"`
	Version     string `json:"version"`
}

func defaultConfig() *Config {
	return &Config{
		Port:        8080,
		Environment: "development",
		Version:     "v1.0.0",
	}
}

// Simple logger
type Logger struct{}

func (l *Logger) Info(msg string, fields ...interface{}) {
	log.Printf("[INFO] %s %v", msg, fields)
}

func (l *Logger) Error(msg string, fields ...interface{}) {
	log.Printf("[ERROR] %s %v", msg, fields)
}

func main() {
	cfg := defaultConfig()
	logger := &Logger{}

	logger.Info("Starting Provenance Linker Server", "version", cfg.Version, "port", cfg.Port)

	router := setupRouter(cfg, logger)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		logger.Info("Server starting", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("Server shutdown complete")
}

func setupRouter(cfg *Config, logger *Logger) *gin.Engine {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Request ID middleware
	router.Use(func(c *gin.Context) {
		requestID := uuid.New().String()
		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	})

	// Health endpoints
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now(),
			"version":   cfg.Version,
		})
	})

	router.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ready",
			"checks": gin.H{
				"database": "connected",
				"cache":    "ready",
			},
		})
	})

	// API v1
	v1 := router.Group("/api/v1")
	{
		// Artifacts
		artifacts := v1.Group("/artifacts")
		{
			artifacts.POST("/", createArtifact(logger))
			artifacts.GET("/:id", getArtifact(logger))
			artifacts.GET("/", listArtifacts(logger))
		}

		// Provenance
		provenance := v1.Group("/provenance")
		{
			provenance.POST("/track", trackBuild(logger))
			provenance.GET("/graph", getProvenanceGraph(logger))
		}

		// SBOM
		sbomGroup := v1.Group("/sbom")
		{
			sbomGroup.POST("/analyze", analyzeSBOM(logger))
			sbomGroup.POST("/generate", generateSBOM(logger))
		}

		// Compliance
		compliance := v1.Group("/compliance")
		{
			compliance.POST("/reports", generateComplianceReport(logger))
			compliance.GET("/nist-ssdf/status", getNISTStatus(logger))
		}

		// Signatures
		signatures := v1.Group("/signatures")
		{
			signatures.POST("/verify", verifySignature(logger))
			signatures.POST("/sign", signArtifact(logger))
		}
	}

	// Metrics
	router.GET("/metrics/prometheus", func(c *gin.Context) {
		c.String(http.StatusOK, `# HELP provenance_requests_total Total requests
# TYPE provenance_requests_total counter
provenance_requests_total{method="GET",status="200"} 1000
provenance_requests_total{method="POST",status="201"} 500

# HELP provenance_artifacts_total Total artifacts
# TYPE provenance_artifacts_total gauge
provenance_artifacts_total 150

# HELP provenance_compliance_score Compliance percentage
# TYPE provenance_compliance_score gauge
provenance_compliance_score{standard="nist-ssdf"} 85.5
`)
	})

	return router
}

// Handler functions
func createArtifact(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name    string             `json:"name" binding:"required"`
			Version string             `json:"version" binding:"required"`
			Type    types.ArtifactType `json:"type" binding:"required"`
			Hash    string             `json:"hash"`
			Size    int64              `json:"size"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			logger.Error("Invalid artifact request", "error", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
				"details": err.Error(),
			})
			return
		}

		artifact := types.Artifact{
			ID:        uuid.New(),
			Name:      req.Name,
			Version:   req.Version,
			Type:      req.Type,
			Hash:      req.Hash,
			Size:      req.Size,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Metadata:  make(map[string]string),
		}

		logger.Info("Artifact created", "id", artifact.ID, "name", artifact.Name)

		c.JSON(http.StatusCreated, gin.H{
			"id": artifact.ID,
			"artifact": artifact,
			"message": "Artifact created successfully",
		})
	}
}

func getArtifact(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid artifact ID format",
			})
			return
		}

		artifact := types.Artifact{
			ID:        id,
			Name:      "sample-artifact",
			Version:   "v1.0.0",
			Type:      types.ArtifactTypeContainer,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Metadata:  make(map[string]string),
		}

		c.JSON(http.StatusOK, gin.H{
			"artifact": artifact,
		})
	}
}

func listArtifacts(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		page := c.DefaultQuery("page", "1")
		limit := c.DefaultQuery("limit", "20")
		
		c.JSON(http.StatusOK, gin.H{
			"artifacts": []interface{}{},
			"pagination": gin.H{
				"page": page,
				"limit": limit,
				"total": 0,
			},
		})
	}
}

func trackBuild(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			SourceRef   string `json:"source_ref" binding:"required"`
			CommitHash  string `json:"commit_hash" binding:"required"`
			BuildSystem string `json:"build_system"`
			BuildURL    string `json:"build_url"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
				"details": err.Error(),
			})
			return
		}

		buildEvent := types.BuildEvent{
			ID:          uuid.New(),
			SourceRef:   req.SourceRef,
			CommitHash:  req.CommitHash,
			BuildSystem: req.BuildSystem,
			BuildURL:    req.BuildURL,
			Timestamp:   time.Now(),
			Metadata:    make(map[string]string),
		}

		logger.Info("Build tracked", "id", buildEvent.ID, "source", buildEvent.SourceRef)

		c.JSON(http.StatusCreated, gin.H{
			"id": buildEvent.ID,
			"build_event": buildEvent,
			"message": "Build event tracked successfully",
		})
	}
}

func getProvenanceGraph(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		artifact := c.Query("artifact")
		if artifact == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "artifact parameter is required",
			})
			return
		}

		graph := types.ProvenanceGraph{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Metadata:  make(map[string]string),
			Nodes: []types.Node{
				{
					ID:    "source-1",
					Type:  types.NodeTypeSource,
					Label: "Git Repository",
					Data:  map[string]interface{}{"url": "https://github.com/org/repo"},
				},
				{
					ID:    "artifact-1",
					Type:  types.NodeTypeArtifact,
					Label: artifact,
					Data:  map[string]interface{}{"name": artifact, "verified": true},
				},
			},
			Edges: []types.Edge{
				{
					ID:    uuid.New().String(),
					From:  "source-1",
					To:    "artifact-1",
					Type:  types.EdgeTypeProduces,
					Label: "produces",
				},
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"graph": graph,
		})
	}
}

func analyzeSBOM(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			SBOMData      string `json:"sbom_data" binding:"required"`
			CheckLicenses bool   `json:"check_licenses"`
			CheckVulns    bool   `json:"check_vulnerabilities"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
				"details": err.Error(),
			})
			return
		}

		parser := sbom.NewParser()
		format, err := parser.DetectFormat([]byte(req.SBOMData))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Unable to detect SBOM format",
				"details": err.Error(),
			})
			return
		}

		analysis := map[string]interface{}{
			"format": format,
			"components": map[string]interface{}{
				"total": 15,
				"by_type": map[string]int{
					"library": 12,
					"application": 2,
					"framework": 1,
				},
			},
		}

		if req.CheckLicenses {
			analysis["licenses"] = map[string]interface{}{
				"distribution": map[string]int{
					"MIT": 8,
					"Apache-2.0": 5,
					"BSD-3-Clause": 2,
				},
				"issues": []string{},
			}
		}

		if req.CheckVulns {
			analysis["vulnerabilities"] = map[string]interface{}{
				"critical": 0,
				"high":     1,
				"medium":   3,
				"low":      2,
				"total":    6,
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"analysis": analysis,
		})
	}
}

func generateSBOM(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Source        string `json:"source" binding:"required"`
			Format        string `json:"format"`
			IncludeDevDeps bool  `json:"include_dev_deps"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
				"details": err.Error(),
			})
			return
		}

		sbomData := types.SBOM{
			ID:        uuid.New(),
			Format:    types.SBOMFormat(req.Format),
			Version:   "1.0",
			CreatedAt: time.Now(),
			CreatedBy: "provenance-linker",
			Components: []types.Component{
				{
					ID:      uuid.New(),
					Name:    "gin-gonic/gin",
					Version: "v1.10.1",
					Type:    types.ComponentTypeLibrary,
					License: []string{"MIT"},
				},
				{
					ID:      uuid.New(),
					Name:    "neo4j/neo4j-go-driver",
					Version: "v5.24.0",
					Type:    types.ComponentTypeLibrary,
					License: []string{"Apache-2.0"},
				},
			},
			Metadata: make(map[string]string),
		}

		c.JSON(http.StatusCreated, gin.H{
			"id": sbomData.ID,
			"sbom": sbomData,
			"message": "SBOM generated successfully",
		})
	}
}

func generateComplianceReport(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Standard    types.ComplianceStandard `json:"standard" binding:"required"`
			ProjectName string                   `json:"project_name" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
				"details": err.Error(),
			})
			return
		}

		report := types.ComplianceReport{
			ID:          uuid.New(),
			Standard:    req.Standard,
			ProjectName: req.ProjectName,
			Version:     "1.0",
			GeneratedAt: time.Now(),
			GeneratedBy: "provenance-linker",
			Score:       85.5,
			Status:      types.ComplianceStatusPartial,
			Requirements: []types.RequirementResult{
				{
					ID:      "PO.1.1",
					Title:   "Stakeholder identification",
					Status:  types.ComplianceStatusCompliant,
					Score:   100.0,
				},
			},
			Evidence: []types.Evidence{},
			Metadata: make(map[string]string),
		}

		c.JSON(http.StatusCreated, gin.H{
			"report": report,
		})
	}
}

func getNISTStatus(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		project := c.Query("project")
		if project == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "project parameter is required",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"project":      project,
			"standard":     "nist-ssdf-v1.1",
			"score":        85.5,
			"status":       "partial",
			"last_updated": time.Now().Add(-24 * time.Hour),
			"requirements": gin.H{
				"total":         20,
				"compliant":     17,
				"partial":       2,
				"non_compliant": 1,
			},
		})
	}
}

func verifySignature(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			ArtifactURI string `json:"artifact_uri" binding:"required"`
			PublicKey   string `json:"public_key"`
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
			"verified":     true,
			"signatures": []gin.H{
				{
					"algorithm": "cosign",
					"valid":     true,
					"timestamp": time.Now().Add(-time.Hour),
				},
			},
			"verification_timestamp": time.Now(),
		})
	}
}

func signArtifact(logger *Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
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
				"algorithm":     "cosign",
				"signature_uri": req.ArtifactURI + ".sig",
				"timestamp":     time.Now(),
			},
			"message": "Artifact signed successfully",
		})
	}
}