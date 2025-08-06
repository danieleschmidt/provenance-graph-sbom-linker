package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/database"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

type ArtifactHandler struct {
	db *database.Neo4jDB
}

func NewArtifactHandler(db *database.Neo4jDB) *ArtifactHandler {
	return &ArtifactHandler{db: db}
}

func (h *ArtifactHandler) CreateArtifact(c *gin.Context) {
	var req struct {
		Name     string            `json:"name" binding:"required"`
		Version  string            `json:"version" binding:"required"`
		Type     string            `json:"type" binding:"required"`
		Hash     string            `json:"hash"`
		Size     int64             `json:"size"`
		Metadata map[string]string `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	artifact := &types.Artifact{
		ID:        uuid.New(),
		Name:      req.Name,
		Version:   req.Version,
		Type:      types.ArtifactType(req.Type),
		Hash:      req.Hash,
		Size:      req.Size,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  req.Metadata,
	}

	if artifact.Metadata == nil {
		artifact.Metadata = make(map[string]string)
	}

	ctx := context.Background()
	if err := h.db.CreateArtifact(ctx, artifact); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create artifact"})
		return
	}

	c.JSON(http.StatusCreated, artifact)
}

func (h *ArtifactHandler) GetArtifact(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID parameter is required"})
		return
	}

	ctx := context.Background()
	artifact, err := h.db.GetArtifact(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Artifact not found"})
		return
	}

	c.JSON(http.StatusOK, artifact)
}

func (h *ArtifactHandler) ListArtifacts(c *gin.Context) {
	limit := 50
	offset := 0

	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
			limit = parsedLimit
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	artifacts := []types.Artifact{
		{
			ID:        uuid.New(),
			Name:      "example-artifact",
			Version:   "1.0.0",
			Type:      types.ArtifactTypeContainer,
			CreatedAt: time.Now().Add(-24 * time.Hour),
			UpdatedAt: time.Now(),
			Metadata:  make(map[string]string),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"artifacts": artifacts,
		"total":     len(artifacts),
		"limit":     limit,
		"offset":    offset,
	})
}