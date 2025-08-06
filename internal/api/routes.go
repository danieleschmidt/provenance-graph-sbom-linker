package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/config"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/database"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/handlers"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/middleware"
)

func SetupRoutes(db *database.Neo4jDB, cfg *config.Config) *gin.Engine {
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS(cfg.Security.CORSOrigins))
	router.Use(middleware.Security())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"service": "provenance-graph-sbom-linker",
		})
	})

	api := router.Group("/api/v1")
	{
		api.GET("/version", handlers.NewVersionHandler().GetVersion)
		
		artifacts := api.Group("/artifacts")
		{
			artifactHandler := handlers.NewArtifactHandler(db)
			artifacts.POST("", artifactHandler.CreateArtifact)
			artifacts.GET("/:id", artifactHandler.GetArtifact)
			artifacts.GET("", artifactHandler.ListArtifacts)
		}

		provenance := api.Group("/provenance")
		{
			provenanceHandler := handlers.NewProvenanceHandler(db)
			provenance.GET("/:id", provenanceHandler.GetProvenance)
			provenance.POST("/track", provenanceHandler.TrackBuild)
		}

		sbom := api.Group("/sbom")
		{
			sbomHandler := handlers.NewSBOMHandler(db)
			sbom.POST("/generate", sbomHandler.GenerateSBOM)
			sbom.POST("/analyze", sbomHandler.AnalyzeSBOM)
		}

		compliance := api.Group("/compliance")
		{
			complianceHandler := handlers.NewComplianceHandler(db)
			compliance.GET("/nist-ssdf/status", complianceHandler.GetNISTSSDF)
			compliance.GET("/eu-cra/status", complianceHandler.GetEUCRA)
		}
	}

	return router
}