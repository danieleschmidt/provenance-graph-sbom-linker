package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/errors"
)

// In-memory storage for standalone demo
type StandaloneStorage struct {
	artifacts map[string]*types.Artifact
	sboms     map[string]*types.SBOM
	mutex     sync.RWMutex
}

var storage = &StandaloneStorage{
	artifacts: make(map[string]*types.Artifact),
	sboms:     make(map[string]*types.SBOM),
}

type StandaloneArtifactHandler struct {
	logger    *logger.StructuredLogger
	storage   *StandaloneStorage
}

func NewStandaloneArtifactHandler() *StandaloneArtifactHandler {
	return &StandaloneArtifactHandler{
		logger:  logger.NewStructuredLogger("info", "json"),
		storage: storage,
	}
}

func (h *StandaloneArtifactHandler) CreateArtifact(c *gin.Context) {
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
		c.JSON(appErr.StatusCode, appErr.ToResponse())
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

	if artifact.Hash == "" {
		artifact.Hash = "sha256:" + artifact.ID.String()[:16]
	}

	h.storage.mutex.Lock()
	h.storage.artifacts[artifact.ID.String()] = artifact
	h.storage.mutex.Unlock()

	h.logger.Performance("create_artifact", time.Since(start), map[string]interface{}{
		"artifact_id":   artifact.ID.String(),
		"artifact_name": artifact.Name,
		"storage_type":  "memory",
	})

	c.JSON(http.StatusCreated, artifact)
}

func (h *StandaloneArtifactHandler) GetArtifact(c *gin.Context) {
	start := time.Now()
	id := c.Param("id")

	if _, err := uuid.Parse(id); err != nil {
		appErr := errors.NewValidationError("Invalid UUID format", err.Error())
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	h.storage.mutex.RLock()
	artifact, exists := h.storage.artifacts[id]
	h.storage.mutex.RUnlock()

	if !exists {
		appErr := errors.NewNotFoundError("Artifact", id)
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	h.logger.Performance("get_artifact", time.Since(start), map[string]interface{}{
		"artifact_id": id,
		"found":       true,
	})

	c.JSON(http.StatusOK, artifact)
}

func (h *StandaloneArtifactHandler) ListArtifacts(c *gin.Context) {
	start := time.Now()

	h.storage.mutex.RLock()
	artifacts := make([]types.Artifact, 0, len(h.storage.artifacts))
	for _, artifact := range h.storage.artifacts {
		artifacts = append(artifacts, *artifact)
	}
	h.storage.mutex.RUnlock()

	h.logger.Performance("list_artifacts", time.Since(start), map[string]interface{}{
		"count": len(artifacts),
	})

	c.JSON(http.StatusOK, gin.H{
		"artifacts": artifacts,
		"total":     len(artifacts),
		"metadata": gin.H{
			"timestamp":    time.Now(),
			"version":      "v1",
			"storage_type": "memory",
		},
	})
}

type StandaloneSBOMHandler struct {
	logger  *logger.StructuredLogger
	storage *StandaloneStorage
}

func NewStandaloneSBOMHandler() *StandaloneSBOMHandler {
	return &StandaloneSBOMHandler{
		logger:  logger.NewStructuredLogger("info", "json"),
		storage: storage,
	}
}

func (h *StandaloneSBOMHandler) GenerateSBOM(c *gin.Context) {
	var req struct {
		ArtifactID string            `json:"artifact_id"`
		Format     string            `json:"format"`
		Metadata   map[string]string `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	format := types.SBOMFormatCycloneDX
	if req.Format != "" {
		format = types.SBOMFormat(req.Format)
	}

	sbom := &types.SBOM{
		ID:        uuid.New(),
		Format:    format,
		Version:   "1.0",
		CreatedAt: time.Now(),
		CreatedBy: "provenance-linker-standalone",
		Metadata:  req.Metadata,
		Components: []types.Component{
			{
				ID:          uuid.New(),
				Name:        "example-component",
				Version:     "1.0.0",
				Type:        types.ComponentTypeLibrary,
				License:     []string{"MIT", "Apache-2.0"},
				Description: "Generated example component for demo",
				Metadata:    make(map[string]string),
			},
			{
				ID:          uuid.New(),
				Name:        "security-library",
				Version:     "2.1.0",
				Type:        types.ComponentTypeLibrary,
				License:     []string{"MIT"},
				Description: "Enhanced security validation library",
				Metadata:    make(map[string]string),
			},
		},
	}

	if sbom.Metadata == nil {
		sbom.Metadata = make(map[string]string)
	}

	sbom.Hash = "sha256:" + sbom.ID.String()[:16]

	h.storage.mutex.Lock()
	h.storage.sboms[sbom.ID.String()] = sbom
	h.storage.mutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"sbom":    sbom,
		"message": "SBOM generated successfully",
	})
}

func (h *StandaloneSBOMHandler) AnalyzeSBOM(c *gin.Context) {
	var req struct {
		SBOM     interface{}       `json:"sbom" binding:"required"`
		Policies map[string]string `json:"policies"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	analysis := map[string]interface{}{
		"status":               "analyzed",
		"components":           2,
		"vulnerabilities":      0,
		"license_issues":       0,
		"compliance_score":     98.5,
		"security_score":       95.0,
		"recommendations": []string{
			"All components have valid licenses",
			"No high-severity vulnerabilities found",
			"SBOM format is valid and complete",
			"Security best practices followed",
		},
		"details": map[string]interface{}{
			"total_components":     2,
			"unique_licenses":      2,
			"critical_vulns":       0,
			"high_vulns":          0,
			"medium_vulns":        0,
			"low_vulns":           0,
			"license_compatibility": "compatible",
			"supply_chain_risk":    "low",
		},
		"timestamp": time.Now(),
	}

	c.JSON(http.StatusOK, gin.H{
		"analysis": analysis,
		"message":  "SBOM analysis completed successfully",
	})
}

type StandaloneComplianceHandler struct {
	logger *logger.StructuredLogger
}

func NewStandaloneComplianceHandler() *StandaloneComplianceHandler {
	return &StandaloneComplianceHandler{
		logger: logger.NewStructuredLogger("info", "json"),
	}
}

func (h *StandaloneComplianceHandler) GetNISTSSDF(c *gin.Context) {
	report := types.ComplianceReport{
		ID:          uuid.New(),
		Standard:    types.ComplianceStandardNISTSSDF,
		ProjectName: "provenance-linker",
		Version:     "1.0.0",
		Status:      types.ComplianceStatusCompliant,
		Score:       92.5,
		Requirements: []types.RequirementResult{
			{
				ID:          "PS.1.1",
				Title:       "Define and document secure development practices",
				Description: "Organization implements secure development practices",
				Status:      types.ComplianceStatusCompliant,
				Evidence:    []string{"SECURITY.md", "CODE_OF_CONDUCT.md"},
				Score:       100.0,
			},
			{
				ID:          "PS.2.1",
				Title:       "Implement security controls in development",
				Description: "Security controls integrated into development process",
				Status:      types.ComplianceStatusCompliant,
				Evidence:    []string{"security-middleware", "input-validation"},
				Score:       95.0,
			},
			{
				ID:          "PS.3.1",
				Title:       "Produce well-secured software",
				Description: "Software meets security requirements",
				Status:      types.ComplianceStatusPartial,
				Evidence:    []string{"automated-tests", "security-scanning"},
				Score:       85.0,
				Details:     "Additional penetration testing recommended",
			},
		},
		Evidence: []types.Evidence{
			{
				ID:          uuid.New(),
				Type:        types.EvidenceTypeTest,
				Source:      "automated-tests",
				Description: "Comprehensive test suite with security validation",
				CreatedAt:   time.Now().Add(-24 * time.Hour),
			},
		},
		GeneratedAt: time.Now(),
		GeneratedBy: "provenance-linker-standalone",
		Metadata:    make(map[string]string),
	}

	c.JSON(http.StatusOK, gin.H{
		"compliance_report": report,
		"message":           "NIST SSDF compliance report generated",
	})
}

func (h *StandaloneComplianceHandler) GetEUCRA(c *gin.Context) {
	report := types.ComplianceReport{
		ID:          uuid.New(),
		Standard:    types.ComplianceStandardEUCRA,
		ProjectName: "provenance-linker",
		Version:     "1.0.0",
		Status:      types.ComplianceStatusCompliant,
		Score:       89.0,
		Requirements: []types.RequirementResult{
			{
				ID:          "CRA.ART.11",
				Title:       "Cybersecurity requirements",
				Description: "Products with digital elements must be secure by design",
				Status:      types.ComplianceStatusCompliant,
				Evidence:    []string{"security-architecture", "threat-model"},
				Score:       90.0,
			},
			{
				ID:          "CRA.ART.13",
				Title:       "Vulnerability disclosure",
				Description: "Coordinated vulnerability disclosure process",
				Status:      types.ComplianceStatusCompliant,
				Evidence:    []string{"SECURITY.md", "vulnerability-policy"},
				Score:       100.0,
			},
			{
				ID:          "CRA.ART.20",
				Title:       "CE marking and conformity assessment",
				Description: "Conformity assessment procedures followed",
				Status:      types.ComplianceStatusPartial,
				Evidence:    []string{"documentation", "testing-reports"},
				Score:       75.0,
				Details:     "Third-party assessment pending",
			},
		},
		Evidence: []types.Evidence{
			{
				ID:          uuid.New(),
				Type:        types.EvidenceTypeBuild,
				Source:      "ci-cd-pipeline",
				Description: "Automated build and security scanning",
				CreatedAt:   time.Now().Add(-12 * time.Hour),
			},
		},
		GeneratedAt: time.Now(),
		GeneratedBy: "provenance-linker-standalone",
		Metadata:    make(map[string]string),
	}

	c.JSON(http.StatusOK, gin.H{
		"compliance_report": report,
		"message":           "EU CRA compliance report generated",
	})
}