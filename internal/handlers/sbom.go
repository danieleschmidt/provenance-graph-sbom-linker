package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/your-org/provenance-graph-sbom-linker/internal/database"
)

type SBOMHandler struct {
	db *database.Neo4jDB
}

func NewSBOMHandler(db *database.Neo4jDB) *SBOMHandler {
	return &SBOMHandler{db: db}
}

func (h *SBOMHandler) GenerateSBOM(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "GenerateSBOM endpoint - implementation pending",
	})
}

func (h *SBOMHandler) AnalyzeSBOM(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "AnalyzeSBOM endpoint - implementation pending",
	})
}