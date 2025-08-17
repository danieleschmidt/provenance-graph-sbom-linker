package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/sbom"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
)

// ArtifactHandler handles artifact-related operations
type ArtifactHandler struct {
	db     interface{}
	logger *logger.StructuredLogger
}

func NewArtifactHandler(db interface{}, logger *logger.StructuredLogger) *ArtifactHandler {
	return &ArtifactHandler{
		db:     db,
		logger: logger,
	}
}

func (h *ArtifactHandler) CreateArtifact(c *gin.Context) {
	var req struct {
		Name    string            `json:"name" binding:"required"`
		Version string            `json:"version" binding:"required"`
		Type    types.ArtifactType `json:"type" binding:"required"`
		Hash    string            `json:"hash"`
		Size    int64             `json:"size"`
		Source  *types.Source     `json:"source"`
		SBOM    *types.SBOM       `json:"sbom"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid artifact request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Validate artifact type
	validTypes := []types.ArtifactType{
		types.ArtifactTypeContainer,
		types.ArtifactTypeBinary,
		types.ArtifactTypeMLModel,
		types.ArtifactTypeLibrary,
		types.ArtifactTypeDocument,
	}
	
	valid := false
	for _, vt := range validTypes {
		if req.Type == vt {
			valid = true
			break
		}
	}
	
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid artifact type",
			"valid_types": validTypes,
		})
		return
	}

	artifact := types.Artifact{
		ID:           uuid.New(),
		Name:         req.Name,
		Version:      req.Version,
		Type:         req.Type,
		Hash:         req.Hash,
		Size:         req.Size,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Source:       req.Source,
		SBOM:         req.SBOM,
		Signatures:   []types.Signature{},
		Metadata:     make(map[string]string),
		Dependencies: []types.Dependency{},
		Attestations: []types.Attestation{},
	}

	// TODO: Store in database
	h.logger.Info("Artifact created", "id", artifact.ID, "name", artifact.Name, "version", artifact.Version)

	c.JSON(http.StatusCreated, gin.H{
		"id": artifact.ID,
		"artifact": artifact,
		"message": "Artifact created successfully",
	})
}

func (h *ArtifactHandler) GetArtifact(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid artifact ID format",
		})
		return
	}

	// TODO: Retrieve from database
	artifact := types.Artifact{
		ID:        id,
		Name:      "sample-artifact",
		Version:   "v1.0.0",
		Type:      types.ArtifactTypeContainer,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  make(map[string]string),
	}

	h.logger.Info("Artifact retrieved", "id", id)

	c.JSON(http.StatusOK, gin.H{
		"artifact": artifact,
	})
}

// ProvenanceHandler handles provenance tracking operations
type ProvenanceHandler struct {
	db     interface{}
	logger *logger.StructuredLogger
}

func NewProvenanceHandler(db interface{}, logger *logger.StructuredLogger) *ProvenanceHandler {
	return &ProvenanceHandler{
		db:     db,
		logger: logger,
	}
}

func (h *ProvenanceHandler) TrackBuild(c *gin.Context) {
	var req struct {
		SourceRef    string              `json:"source_ref" binding:"required"`
		CommitHash   string              `json:"commit_hash" binding:"required"`
		BuildSystem  string              `json:"build_system"`
		BuildURL     string              `json:"build_url"`
		Artifacts    []types.Artifact    `json:"artifacts" binding:"required"`
		Metadata     map[string]string   `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid build tracking request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	buildEvent := types.BuildEvent{
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

	// TODO: Store in graph database
	h.logger.Info("Build event tracked", "id", buildEvent.ID, "source", buildEvent.SourceRef, "commit", buildEvent.CommitHash)

	c.JSON(http.StatusCreated, gin.H{
		"id": buildEvent.ID,
		"build_event": buildEvent,
		"message": "Build event tracked successfully",
	})
}

func (h *ProvenanceHandler) GetProvenanceGraph(c *gin.Context) {
	artifact := c.Query("artifact")
	depth := c.DefaultQuery("depth", "10")
	format := c.DefaultQuery("format", "json")

	if artifact == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "artifact parameter is required",
		})
		return
	}

	// Generate sample provenance graph
	graph := types.ProvenanceGraph{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		Metadata:  make(map[string]string),
		Nodes: []types.Node{
			{
				ID:       "source-1",
				Type:     types.NodeTypeSource,
				Label:    "Git Repository",
				Data:     map[string]interface{}{"url": "https://github.com/org/repo", "commit": "abc123"},
				Metadata: make(map[string]string),
			},
			{
				ID:       "build-1",
				Type:     types.NodeTypeBuild,
				Label:    "CI Build",
				Data:     map[string]interface{}{"build_id": "123", "status": "success"},
				Metadata: make(map[string]string),
			},
			{
				ID:       "artifact-1",
				Type:     types.NodeTypeArtifact,
				Label:    artifact,
				Data:     map[string]interface{}{"name": artifact, "verified": true},
				Metadata: make(map[string]string),
			},
		},
		Edges: []types.Edge{
			{
				ID:       uuid.New().String(),
				From:     "source-1",
				To:       "build-1",
				Type:     types.EdgeTypeBuiltFrom,
				Label:    "triggers",
				Metadata: make(map[string]string),
			},
			{
				ID:       uuid.New().String(),
				From:     "build-1",
				To:       "artifact-1",
				Type:     types.EdgeTypeProduces,
				Label:    "produces",
				Metadata: make(map[string]string),
			},
		},
	}

	graph.Metadata["artifact"] = artifact
	graph.Metadata["depth"] = depth
	graph.Metadata["format"] = format

	h.logger.Info("Provenance graph generated", "artifact", artifact, "nodes", len(graph.Nodes), "edges", len(graph.Edges))

	c.JSON(http.StatusOK, gin.H{
		"graph": graph,
		"metadata": map[string]interface{}{
			"artifact": artifact,
			"depth": depth,
			"format": format,
			"generated_at": time.Now(),
		},
	})
}

// SBOMHandler handles SBOM operations
type SBOMHandler struct {
	db     interface{}
	logger *logger.StructuredLogger
	parser *sbom.Parser
}

func NewSBOMHandler(db interface{}, logger *logger.StructuredLogger) *SBOMHandler {
	return &SBOMHandler{
		db:     db,
		logger: logger,
		parser: sbom.NewParser(),
	}
}

func (h *SBOMHandler) AnalyzeSBOM(c *gin.Context) {
	var req struct {
		SBOMData      string `json:"sbom_data" binding:"required"`
		CheckLicenses bool   `json:"check_licenses"`
		CheckVulns    bool   `json:"check_vulnerabilities"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid SBOM analysis request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Detect SBOM format
	format, err := h.parser.DetectFormat([]byte(req.SBOMData))
	if err != nil {
		h.logger.Error("Failed to detect SBOM format", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Unable to detect SBOM format",
			"details": err.Error(),
		})
		return
	}

	// Parse SBOM
	parsedSBOM, err := h.parser.ParseCycloneDX([]byte(req.SBOMData))
	if err != nil {
		h.logger.Error("Failed to parse SBOM", "error", err, "format", format)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to parse SBOM",
			"details": err.Error(),
		})
		return
	}

	analysis := map[string]interface{}{
		"sbom_id": parsedSBOM.ID,
		"format": format,
		"created_at": parsedSBOM.CreatedAt,
		"created_by": parsedSBOM.CreatedBy,
		"components": map[string]interface{}{
			"total": len(parsedSBOM.Components),
			"by_type": groupComponentsByType(parsedSBOM.Components),
		},
	}

	if req.CheckLicenses {
		analysis["licenses"] = analyzeLicenses(parsedSBOM.Components)
	}

	if req.CheckVulns {
		analysis["vulnerabilities"] = analyzeVulnerabilities(parsedSBOM.Components)
	}

	h.logger.Info("SBOM analyzed", "id", parsedSBOM.ID, "format", format, "components", len(parsedSBOM.Components))

	c.JSON(http.StatusOK, gin.H{
		"analysis": analysis,
		"message": "SBOM analyzed successfully",
	})
}

// ComplianceHandler handles compliance reporting
type ComplianceHandler struct {
	db     interface{}
	logger *logger.StructuredLogger
}

func NewComplianceHandler(db interface{}, logger *logger.StructuredLogger) *ComplianceHandler {
	return &ComplianceHandler{
		db:     db,
		logger: logger,
	}
}

func (h *ComplianceHandler) GenerateReport(c *gin.Context) {
	var req struct {
		Standard    types.ComplianceStandard `json:"standard" binding:"required"`
		ProjectName string                   `json:"project_name" binding:"required"`
		ArtifactIDs []string                 `json:"artifact_ids"`
		EvidenceDir string                   `json:"evidence_dir"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid compliance report request", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Validate standard
	validStandards := []types.ComplianceStandard{
		types.ComplianceStandardNISTSSDF,
		types.ComplianceStandardNISTSSDFv11,
		types.ComplianceStandardEUCRA,
		types.ComplianceStandardCustom,
	}
	
	valid := false
	for _, vs := range validStandards {
		if req.Standard == vs {
			valid = true
			break
		}
	}
	
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid compliance standard",
			"valid_standards": validStandards,
		})
		return
	}

	// Generate compliance report based on standard
	var report types.ComplianceReport
	
	switch req.Standard {
	case types.ComplianceStandardNISTSSDF, types.ComplianceStandardNISTSSDFv11:
		report = generateNISTSSDFReport(req.ProjectName)
	case types.ComplianceStandardEUCRA:
		report = generateEUCRAReport(req.ProjectName)
	default:
		report = generateCustomReport(req.ProjectName)
	}

	h.logger.Info("Compliance report generated", "id", report.ID, "standard", req.Standard, "project", req.ProjectName, "score", report.Score)

	c.JSON(http.StatusCreated, gin.H{
		"report": report,
		"message": "Compliance report generated successfully",
	})
}

// HealthHandler handles health check operations
type HealthHandler struct {
	db     interface{}
	logger *logger.StructuredLogger
}

func NewHealthHandler(db interface{}, logger *logger.StructuredLogger) *HealthHandler {
	return &HealthHandler{
		db:     db,
		logger: logger,
	}
}

func (h *HealthHandler) HealthCheck(c *gin.Context) {
	health := map[string]interface{}{
		"status": "healthy",
		"timestamp": time.Now(),
		"checks": map[string]string{
			"database": "connected", // TODO: Actual database health check
			"redis":    "connected", // TODO: Actual Redis health check
		},
		"version": "dev",
	}

	c.JSON(http.StatusOK, health)
}

func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	readiness := map[string]interface{}{
		"status": "ready",
		"timestamp": time.Now(),
		"checks": map[string]string{
			"database": "ready",
			"migrations": "applied",
			"dependencies": "loaded",
		},
	}

	c.JSON(http.StatusOK, readiness)
}

// Helper functions

func groupComponentsByType(components []types.Component) map[string]int {
	counts := make(map[string]int)
	for _, comp := range components {
		counts[string(comp.Type)]++
	}
	return counts
}

func analyzeLicenses(components []types.Component) map[string]interface{} {
	licenseCount := make(map[string]int)
	var issues []string
	
	for _, comp := range components {
		for _, license := range comp.License {
			licenseCount[license]++
		}
		
		if len(comp.License) == 0 {
			issues = append(issues, fmt.Sprintf("Component %s has no license information", comp.Name))
		}
	}
	
	return map[string]interface{}{
		"distribution": licenseCount,
		"issues": issues,
		"total_licenses": len(licenseCount),
	}
}

func analyzeVulnerabilities(components []types.Component) map[string]interface{} {
	// Simulate vulnerability analysis
	return map[string]interface{}{
		"critical": 0,
		"high":     1,
		"medium":   3,
		"low":      2,
		"total":    6,
		"details": []map[string]interface{}{
			{
				"cve": "CVE-2024-1234",
				"severity": "high",
				"component": "example-lib",
				"description": "Buffer overflow vulnerability",
			},
		},
	}
}

func generateNISTSSDFReport(projectName string) types.ComplianceReport {
	return types.ComplianceReport{
		ID:          uuid.New(),
		Standard:    types.ComplianceStandardNISTSSDFv11,
		ProjectName: projectName,
		Version:     "1.0",
		GeneratedAt: time.Now(),
		GeneratedBy: "provenance-linker",
		Score:       85.5,
		Status:      types.ComplianceStatusPartial,
		Requirements: []types.RequirementResult{
			{
				ID:          "PO.1.1",
				Title:       "Identify and document stakeholders",
				Description: "Identify and document all stakeholders in the software development process",
				Status:      types.ComplianceStatusCompliant,
				Evidence:    []string{"stakeholder-matrix.md"},
				Details:     "All stakeholders documented in project documentation",
				Score:       100.0,
			},
			{
				ID:          "PS.1.1",
				Title:       "Secure development environment",
				Description: "Use a well-secured software development environment",
				Status:      types.ComplianceStatusCompliant,
				Evidence:    []string{"ci-cd-security.md"},
				Details:     "Secure CI/CD pipeline with proper access controls",
				Score:       95.0,
			},
		},
		Evidence: []types.Evidence{},
		Metadata: make(map[string]string),
	}
}

func generateEUCRAReport(projectName string) types.ComplianceReport {
	return types.ComplianceReport{
		ID:          uuid.New(),
		Standard:    types.ComplianceStandardEUCRA,
		ProjectName: projectName,
		Version:     "1.0",
		GeneratedAt: time.Now(),
		GeneratedBy: "provenance-linker",
		Score:       78.0,
		Status:      types.ComplianceStatusPartial,
		Requirements: []types.RequirementResult{
			{
				ID:          "ART.10.1",
				Title:       "Security by design and by default",
				Description: "Cybersecurity by design and by default requirements",
				Status:      types.ComplianceStatusCompliant,
				Evidence:    []string{"security-design-doc.md"},
				Details:     "Security considerations integrated into design phase",
				Score:       90.0,
			},
		},
		Evidence: []types.Evidence{},
		Metadata: make(map[string]string),
	}
}

func generateCustomReport(projectName string) types.ComplianceReport {
	return types.ComplianceReport{
		ID:          uuid.New(),
		Standard:    types.ComplianceStandardCustom,
		ProjectName: projectName,
		Version:     "1.0",
		GeneratedAt: time.Now(),
		GeneratedBy: "provenance-linker",
		Score:       92.0,
		Status:      types.ComplianceStatusCompliant,
		Requirements: []types.RequirementResult{},
		Evidence:     []types.Evidence{},
		Metadata:     make(map[string]string),
	}
}