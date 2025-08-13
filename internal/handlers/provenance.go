package handlers

import (
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

type ProvenanceHandler struct {
	db        *database.Neo4jDB
	logger    *logger.StructuredLogger
	validator *validation.SecurityValidator
}

func NewProvenanceHandler(db *database.Neo4jDB) *ProvenanceHandler {
	return &ProvenanceHandler{
		db:        db,
		logger:    logger.NewStructuredLogger("info", "json"),
		validator: validation.NewSecurityValidator([]string{}, []string{}),
	}
}

func (h *ProvenanceHandler) GetProvenance(c *gin.Context) {
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

	// Get depth parameter (default 5)
	depth := 5
	if depthStr := c.Query("depth"); depthStr != "" {
		if parsedDepth, err := strconv.Atoi(depthStr); err == nil && parsedDepth > 0 && parsedDepth <= 20 {
			depth = parsedDepth
		}
	}

	graph, err := h.db.GetProvenanceGraph(ctx, id, depth)
	if err != nil {
		appErr := errors.NewNotFoundError("Provenance graph", id)
		h.logger.LogError(ctx, appErr, "get_provenance", map[string]interface{}{
			"artifact_id": id,
			"depth":       depth,
		})
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Log performance
	h.logger.Performance("get_provenance", time.Since(start), map[string]interface{}{
		"artifact_id": id,
		"depth":       depth,
		"nodes":       len(graph.Nodes),
		"edges":       len(graph.Edges),
	})

	c.JSON(http.StatusOK, graph)
}

func (h *ProvenanceHandler) TrackBuild(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	var req struct {
		SourceRef    string               `json:"source_ref" binding:"required"`
		CommitHash   string               `json:"commit_hash" binding:"required"`
		BuildID      string               `json:"build_id"`
		BuildSystem  string               `json:"build_system"`
		BuildURL     string               `json:"build_url"`
		Artifacts    []types.Artifact     `json:"artifacts" binding:"required"`
		Metadata     map[string]string    `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		appErr := errors.NewValidationError("Invalid request format", err.Error())
		h.logger.LogError(ctx, appErr, "bind_request", map[string]interface{}{
			"operation": "track_build",
			"client_ip": c.ClientIP(),
		})
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Sanitize inputs
	req.SourceRef = h.validator.SanitizeInput(req.SourceRef)
	req.CommitHash = h.validator.SanitizeInput(req.CommitHash)
	req.BuildSystem = h.validator.SanitizeInput(req.BuildSystem)

	// Create build event
	buildEvent := &types.BuildEvent{
		ID:          uuid.New(),
		SourceRef:   req.SourceRef,
		CommitHash:  req.CommitHash,
		BuildID:     req.BuildID,
		BuildSystem: req.BuildSystem,
		BuildURL:    req.BuildURL,
		Artifacts:   req.Artifacts,
		Timestamp:   time.Now(),
		Metadata:    req.Metadata,
	}

	if buildEvent.Metadata == nil {
		buildEvent.Metadata = make(map[string]string)
	}

	// Create build event in database
	if err := h.db.CreateBuildEvent(ctx, buildEvent); err != nil {
		appErr := errors.NewDatabaseError("create_build_event", err)
		h.logger.LogError(ctx, appErr, "database_operation", map[string]interface{}{
			"build_id":    buildEvent.ID.String(),
			"source_ref":  buildEvent.SourceRef,
			"commit_hash": buildEvent.CommitHash,
		})
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Create source if needed
	source := &types.Source{
		ID:         uuid.New(),
		Type:       types.SourceTypeGit,
		URL:        req.SourceRef,
		Branch:     "main", // Default, could be parsed from source_ref
		CommitHash: req.CommitHash,
		CreatedAt:  time.Now(),
		Metadata:   make(map[string]string),
	}

	if err := h.db.CreateSource(ctx, source); err != nil {
		h.logger.LogError(ctx, errors.NewDatabaseError("create_source", err), "database_operation", map[string]interface{}{
			"source_id": source.ID.String(),
			"url":       source.URL,
		})
		// Continue despite source creation failure
	}

	// Create artifacts and link them to the build
	for i := range buildEvent.Artifacts {
		artifact := &buildEvent.Artifacts[i]
		if artifact.ID == (uuid.UUID{}) {
			artifact.ID = uuid.New()
		}
		if artifact.CreatedAt.IsZero() {
			artifact.CreatedAt = time.Now()
		}
		if artifact.UpdatedAt.IsZero() {
			artifact.UpdatedAt = time.Now()
		}

		if err := h.db.CreateArtifact(ctx, artifact); err != nil {
			h.logger.LogError(ctx, errors.NewDatabaseError("create_artifact", err), "database_operation", map[string]interface{}{
				"artifact_id":   artifact.ID.String(),
				"artifact_name": artifact.Name,
			})
			// Continue with other artifacts
			continue
		}

		// Create provenance link from build to artifact
		if err := h.db.CreateProvenanceLink(ctx, buildEvent.ID.String(), artifact.ID.String(), "PRODUCES"); err != nil {
			h.logger.LogError(ctx, errors.NewDatabaseError("create_provenance_link", err), "database_operation", map[string]interface{}{
				"build_id":     buildEvent.ID.String(),
				"artifact_id":  artifact.ID.String(),
			})
		}
	}

	// Log successful build tracking
	h.logger.Performance("track_build", time.Since(start), map[string]interface{}{
		"build_id":      buildEvent.ID.String(),
		"artifacts_count": len(buildEvent.Artifacts),
		"source_ref":    buildEvent.SourceRef,
	})

	h.logger.Audit("track_build", c.GetString("user_id"), buildEvent.ID.String(), true, map[string]interface{}{
		"source_ref":  buildEvent.SourceRef,
		"commit_hash": buildEvent.CommitHash,
		"build_system": buildEvent.BuildSystem,
	})

	c.JSON(http.StatusCreated, buildEvent)
}

func (h *ProvenanceHandler) GetProvenanceGraph(c *gin.Context) {
	// Alias for GetProvenance for backward compatibility
	h.GetProvenance(c)
}