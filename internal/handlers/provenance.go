package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/your-org/provenance-graph-sbom-linker/internal/database"
)

type ProvenanceHandler struct {
	db *database.Neo4jDB
}

func NewProvenanceHandler(db *database.Neo4jDB) *ProvenanceHandler {
	return &ProvenanceHandler{db: db}
}

func (h *ProvenanceHandler) GetProvenance(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GetProvenance endpoint - implementation pending",
		"id":      id,
	})
}

func (h *ProvenanceHandler) TrackBuild(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "TrackBuild endpoint - implementation pending",
	})
}