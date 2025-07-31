package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/your-org/provenance-graph-sbom-linker/internal/database"
)

type ArtifactHandler struct {
	db *database.Neo4jDB
}

func NewArtifactHandler(db *database.Neo4jDB) *ArtifactHandler {
	return &ArtifactHandler{db: db}
}

func (h *ArtifactHandler) CreateArtifact(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "CreateArtifact endpoint - implementation pending",
	})
}

func (h *ArtifactHandler) GetArtifact(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetArtifact endpoint - implementation pending",
		"id":      id,
	})
}

func (h *ArtifactHandler) ListArtifacts(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "ListArtifacts endpoint - implementation pending",
	})
}