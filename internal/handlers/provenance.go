package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/database"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

type ProvenanceHandler struct {
	db *database.Neo4jDB
}

func NewProvenanceHandler(db *database.Neo4jDB) *ProvenanceHandler {
	return &ProvenanceHandler{db: db}
}

func (h *ProvenanceHandler) GetProvenance(c *gin.Context) {
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

	graph := &types.ProvenanceGraph{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		Metadata:  make(map[string]string),
		Nodes: []types.Node{
			{
				ID:       artifact.ID.String(),
				Type:     types.NodeTypeArtifact,
				Label:    artifact.Name + ":" + artifact.Version,
				Data:     artifact,
				Metadata: make(map[string]string),
			},
		},
		Edges: []types.Edge{},
	}

	c.JSON(http.StatusOK, gin.H{
		"provenance": graph,
		"message":    "Provenance graph generated",
	})
}

func (h *ProvenanceHandler) TrackBuild(c *gin.Context) {
	var req struct {
		SourceRef    string            `json:"source_ref" binding:"required"`
		CommitHash   string            `json:"commit_hash" binding:"required"`
		BuildSystem  string            `json:"build_system"`
		BuildURL     string            `json:"build_url"`
		Artifacts    []types.Artifact  `json:"artifacts" binding:"required"`
		Metadata     map[string]string `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	buildEvent := &types.BuildEvent{
		ID:          uuid.New(),
		SourceRef:   req.SourceRef,
		CommitHash:  req.CommitHash,
		BuildSystem: req.BuildSystem,
		BuildURL:    req.BuildURL,
		Artifacts:   req.Artifacts,
		Timestamp:   time.Now(),
		Metadata:    req.Metadata,
	}

	if buildEvent.Metadata == nil {
		buildEvent.Metadata = make(map[string]string)
	}

	ctx := context.Background()
	for _, artifact := range buildEvent.Artifacts {
		if artifact.ID == (uuid.UUID{}) {
			artifact.ID = uuid.New()
		}
		if artifact.CreatedAt.IsZero() {
			artifact.CreatedAt = time.Now()
			artifact.UpdatedAt = time.Now()
		}
		if err := h.db.CreateArtifact(ctx, &artifact); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store artifact"})
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"build_event": buildEvent,
		"message":     "Build tracking completed",
	})
}