package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/database"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/errors"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/validation"
)

// DatabaseInterface defines the methods required by the artifact handler
type DatabaseInterface interface {
	CreateArtifact(ctx context.Context, artifact *types.Artifact) error
	GetArtifact(ctx context.Context, id string) (*types.Artifact, error)
	Close() error
}

// Neo4jDBAdapter adapts the Neo4jDB to the DatabaseInterface
type Neo4jDBAdapter struct {
	db *database.Neo4jDB
}

func NewNeo4jDBAdapter(db *database.Neo4jDB) *Neo4jDBAdapter {
	return &Neo4jDBAdapter{db: db}
}

func (a *Neo4jDBAdapter) CreateArtifact(ctx context.Context, artifact *types.Artifact) error {
	return a.db.CreateArtifact(ctx, artifact)
}

func (a *Neo4jDBAdapter) GetArtifact(ctx context.Context, id string) (*types.Artifact, error) {
	return a.db.GetArtifact(ctx, id)
}

func (a *Neo4jDBAdapter) Close() error {
	return a.db.Close()
}

type ArtifactHandler struct {
	db        DatabaseInterface
	logger    *logger.StructuredLogger
	validator *validation.SecurityValidator
}

func NewArtifactHandler(db DatabaseInterface) *ArtifactHandler {
	// For now, use simplified constructors to get the system working
	logger := logger.NewStructuredLogger("info", "json")
	validator := validation.NewSecurityValidator([]string{}, []string{})
	
	return &ArtifactHandler{
		db:        db,
		logger:    logger,
		validator: validator,
	}
}

func (h *ArtifactHandler) CreateArtifact(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	var req struct {
		Name     string            `json:"name" binding:"required"`
		Version  string            `json:"version" binding:"required"`
		Type     string            `json:"type" binding:"required"`
		Hash     string            `json:"hash"`
		Size     int64             `json:"size"`
		Metadata map[string]string `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		appErr := errors.NewValidationError("Invalid request format", err.Error())
		h.logger.LogError(ctx, appErr, "bind_request", map[string]interface{}{
			"operation": "create_artifact",
			"client_ip": c.ClientIP(),
		})
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Sanitize inputs
	req.Name = h.validator.SanitizeInput(req.Name)
	req.Version = h.validator.SanitizeInput(req.Version)
	req.Type = h.validator.SanitizeInput(req.Type)

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

	// Validate artifact
	validationResult := h.validator.ValidateArtifact(artifact)
	if !validationResult.Valid {
		appErr := errors.NewValidationError("Artifact validation failed", "See validation errors")
		for _, valErr := range validationResult.Errors {
			appErr.WithContext(valErr.Field, valErr.Message)
		}
		h.logger.LogError(ctx, appErr, "validate_artifact", map[string]interface{}{
			"artifact_name": artifact.Name,
			"errors":       validationResult.Errors,
		})
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Generate hash if not provided
	if artifact.Hash == "" {
		artifact.Hash = validation.GenerateSecureHash(artifact.Name + artifact.Version)
	}

	if err := h.db.CreateArtifact(ctx, artifact); err != nil {
		appErr := errors.NewDatabaseError("create_artifact", err)
		h.logger.LogError(ctx, appErr, "database_operation", map[string]interface{}{
			"artifact_id":   artifact.ID.String(),
			"artifact_name": artifact.Name,
		})
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Log successful creation
	h.logger.Performance("create_artifact", time.Since(start), map[string]interface{}{
		"artifact_id":   artifact.ID.String(),
		"artifact_name": artifact.Name,
		"artifact_type": string(artifact.Type),
	})

	h.logger.Audit("create_artifact", c.GetString("user_id"), artifact.ID.String(), true, map[string]interface{}{
		"artifact_name": artifact.Name,
		"artifact_type": string(artifact.Type),
	})

	c.JSON(http.StatusCreated, artifact)
}

func (h *ArtifactHandler) GetArtifact(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	id := c.Param("id")
	if id == "" {
		appErr := errors.NewValidationError("ID parameter is required", "")
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(id); err != nil {
		appErr := errors.NewValidationError("Invalid UUID format", err.Error())
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	artifact, err := h.db.GetArtifact(ctx, id)
	if err != nil {
		appErr := errors.NewNotFoundError("Artifact", id)
		h.logger.LogError(ctx, appErr, "get_artifact", map[string]interface{}{
			"artifact_id": id,
		})
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Log successful retrieval
	h.logger.Performance("get_artifact", time.Since(start), map[string]interface{}{
		"artifact_id":   id,
		"artifact_name": artifact.Name,
	})

	c.JSON(http.StatusOK, artifact)
}

func (h *ArtifactHandler) ListArtifacts(c *gin.Context) {
	start := time.Now()

	limit := 50
	offset := 0
	maxLimit := 1000

	// Parse and validate limit
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err != nil {
			appErr := errors.NewValidationError("Invalid limit parameter", err.Error())
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			return
		} else if parsedLimit <= 0 {
			appErr := errors.NewValidationError("Limit must be positive", "")
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			return
		} else if parsedLimit > maxLimit {
			appErr := errors.NewValidationError("Limit exceeds maximum", fmt.Sprintf("Maximum limit is %d", maxLimit))
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			return
		} else {
			limit = parsedLimit
		}
	}

	// Parse and validate offset
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err != nil {
			appErr := errors.NewValidationError("Invalid offset parameter", err.Error())
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			return
		} else if parsedOffset < 0 {
			appErr := errors.NewValidationError("Offset must be non-negative", "")
			c.JSON(appErr.StatusCode, appErr.ToResponse())
			return
		} else {
			offset = parsedOffset
		}
	}

	// TODO: Replace with actual database query
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

	// Log performance
	h.logger.Performance("list_artifacts", time.Since(start), map[string]interface{}{
		"limit":  limit,
		"offset": offset,
		"count":  len(artifacts),
	})

	c.JSON(http.StatusOK, gin.H{
		"artifacts": artifacts,
		"total":     len(artifacts),
		"limit":     limit,
		"offset":    offset,
		"metadata": gin.H{
			"timestamp": time.Now(),
			"version":   "v1",
		},
	})
}