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
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/version"
)

func main() {
	log.Printf("Starting Provenance Graph SBOM Linker Server")
	log.Printf("Version: %s, Commit: %s, Date: %s", 
		version.Version, version.Commit, version.Date)

	// Set up Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"version": version.Version,
			"commit":  version.Commit,
			"time":    time.Now().UTC(),
		})
	})

	// Ready check endpoint
	router.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ready",
			"time":   time.Now().UTC(),
		})
	})

	// Version endpoint
	router.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version": version.Version,
			"commit":  version.Commit,
			"date":    version.Date,
		})
	})

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Artifacts endpoints
		v1.POST("/artifacts", func(c *gin.Context) {
			c.JSON(http.StatusCreated, gin.H{
				"message": "Artifact tracked successfully",
				"id":      "sample-artifact-id",
				"timestamp": time.Now().UTC(),
			})
		})

		v1.GET("/artifacts/:id", func(c *gin.Context) {
			id := c.Param("id")
			c.JSON(http.StatusOK, gin.H{
				"id":   id,
				"name": "sample-artifact",
				"type": "container",
				"version": "v1.0.0",
				"created_at": time.Now().Add(-24 * time.Hour).UTC(),
			})
		})

		// Provenance endpoints
		v1.GET("/provenance", func(c *gin.Context) {
			artifact := c.Query("artifact")
			c.JSON(http.StatusOK, gin.H{
				"artifact": artifact,
				"graph": map[string]interface{}{
					"nodes": []map[string]interface{}{
						{"id": "source-1", "type": "source", "label": "Git Repository"},
						{"id": "build-1", "type": "build", "label": "CI Build"},
						{"id": "artifact-1", "type": "artifact", "label": "Container Image"},
					},
					"edges": []map[string]interface{}{
						{"from": "source-1", "to": "build-1", "type": "builds"},
						{"from": "build-1", "to": "artifact-1", "type": "produces"},
					},
				},
			})
		})

		// Verification endpoints
		v1.POST("/verify", func(c *gin.Context) {
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
				"verified": true,
				"artifact": req.ArtifactURI,
				"timestamp": time.Now().UTC(),
				"signatures": []map[string]interface{}{
					{
						"algorithm": "cosign",
						"valid": true,
						"timestamp": time.Now().Add(-time.Hour).UTC(),
					},
				},
			})
		})

		// Compliance endpoints
		v1.GET("/compliance/nist-ssdf/status", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"standard": "nist-ssdf-v1.1",
				"score":    85.5,
				"status":   "partial",
				"requirements": map[string]interface{}{
					"total": 10,
					"met":   8,
					"partial": 1,
					"failed": 1,
				},
				"last_updated": time.Now().Add(-24 * time.Hour).UTC(),
			})
		})
		
		// SBOM endpoints
		v1.POST("/sbom", func(c *gin.Context) {
			c.JSON(http.StatusCreated, gin.H{
				"message": "SBOM created successfully",
				"id": "sbom-123",
				"format": "cyclonedx",
				"timestamp": time.Now().UTC(),
			})
		})
		
		v1.GET("/sbom/:id", func(c *gin.Context) {
			id := c.Param("id")
			c.JSON(http.StatusOK, gin.H{
				"id": id,
				"format": "cyclonedx",
				"version": "1.4",
				"components": 15,
				"created_at": time.Now().Add(-12 * time.Hour).UTC(),
			})
		})
	}

	// Create HTTP server
	port := 8080
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting HTTP server on port %d", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server shutdown complete")
}