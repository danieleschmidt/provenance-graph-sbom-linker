package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/your-org/provenance-graph-sbom-linker/internal/version"
)

type VersionHandler struct{}

func NewVersionHandler() *VersionHandler {
	return &VersionHandler{}
}

func (h *VersionHandler) GetVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version": version.Version,
		"commit":  version.Commit,
		"date":    version.Date,
	})
}