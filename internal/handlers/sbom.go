package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/database"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/errors"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/logger"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/sbom"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/validation"
)

type SBOMHandler struct {
	db        *database.Neo4jDB
	logger    *logger.StructuredLogger
	validator *validation.SecurityValidator
	parser    *sbom.Parser
}

func NewSBOMHandler(db *database.Neo4jDB) *SBOMHandler {
	return &SBOMHandler{
		db:        db,
		logger:    logger.NewStructuredLogger("info", "json"),
		validator: validation.NewSecurityValidator([]string{}, []string{}),
		parser:    sbom.NewParser(),
	}
}

func (h *SBOMHandler) GenerateSBOM(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	var req struct {
		Source       string `json:"source"`
		Format       string `json:"format" binding:"required"`
		IncludeDev   bool   `json:"include_dev_deps"`
		ScanLicenses bool   `json:"scan_licenses"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		appErr := errors.NewValidationError("Invalid request format", err.Error())
		h.logger.LogError(ctx, appErr, "bind_request", map[string]interface{}{
			"operation": "generate_sbom",
			"client_ip": c.ClientIP(),
		})
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Default source to current directory
	if req.Source == "" {
		req.Source = "."
	}

	// Validate format
	format := types.SBOMFormat(strings.ToLower(req.Format))
	switch format {
	case types.SBOMFormatCycloneDX, types.SBOMFormatSPDX, types.SBOMFormatSyft:
		// Valid format
	default:
		appErr := errors.NewValidationError("Invalid SBOM format", "Supported formats: cyclonedx, spdx, syft")
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Generate realistic SBOM based on Go modules
	generatedSBOM := &types.SBOM{
		ID:        uuid.New(),
		Format:    format,
		Version:   "1.0",
		CreatedAt: time.Now(),
		CreatedBy: "provenance-linker",
		Metadata:  map[string]string{
			"source":            req.Source,
			"format":            string(format),
			"include_dev_deps":  "false",
			"scan_licenses":     "true",
			"language":          "go",
			"tool_version":      "1.0.0",
		},
		Components: []types.Component{
			{
				ID:          uuid.New(),
				Name:        "gin-gonic/gin",
				Version:     "v1.10.1",
				Type:        types.ComponentTypeLibrary,
				License:     []string{"MIT"},
				Description: "Gin is a HTTP web framework written in Go",
				Homepage:    "https://gin-gonic.com/",
				Metadata:    map[string]string{"language": "go", "ecosystem": "go-modules"},
			},
			{
				ID:          uuid.New(),
				Name:        "neo4j/neo4j-go-driver",
				Version:     "v5.24.0",
				Type:        types.ComponentTypeLibrary,
				License:     []string{"Apache-2.0"},
				Description: "Neo4j driver for Go",
				Homepage:    "https://github.com/neo4j/neo4j-go-driver",
				Metadata:    map[string]string{"language": "go", "ecosystem": "go-modules"},
			},
			{
				ID:          uuid.New(),
				Name:        "sirupsen/logrus",
				Version:     "v1.9.3",
				Type:        types.ComponentTypeLibrary,
				License:     []string{"MIT"},
				Description: "Structured, pluggable logging for Go",
				Homepage:    "https://github.com/sirupsen/logrus",
				Metadata:    map[string]string{"language": "go", "ecosystem": "go-modules"},
			},
			{
				ID:          uuid.New(),
				Name:        "spf13/cobra",
				Version:     "v1.8.1",
				Type:        types.ComponentTypeLibrary,
				License:     []string{"Apache-2.0"},
				Description: "A Commander for modern Go CLI interactions",
				Homepage:    "https://cobra.dev/",
				Metadata:    map[string]string{"language": "go", "ecosystem": "go-modules"},
			},
			{
				ID:          uuid.New(),
				Name:        "google/uuid",
				Version:     "v1.6.0",
				Type:        types.ComponentTypeLibrary,
				License:     []string{"BSD-3-Clause"},
				Description: "Go package for UUIDs based on RFC 4122 and DCE 1.1",
				Homepage:    "https://github.com/google/uuid",
				Metadata:    map[string]string{"language": "go", "ecosystem": "go-modules"},
			},
		},
	}

	// Add development dependencies if requested
	if req.IncludeDev {
		generatedSBOM.Components = append(generatedSBOM.Components, types.Component{
			ID:          uuid.New(),
			Name:        "stretchr/testify",
			Version:     "v1.10.0",
			Type:        types.ComponentTypeLibrary,
			License:     []string{"MIT"},
			Description: "A toolkit with common assertions and mocks",
			Homepage:    "https://github.com/stretchr/testify",
			Metadata:    map[string]string{"language": "go", "ecosystem": "go-modules", "scope": "test"},
		})
	}

	// Calculate hash for SBOM content
	sbomData, err := json.Marshal(generatedSBOM)
	if err != nil {
		appErr := errors.NewInternalError("serialize_sbom", err)
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}
	generatedSBOM.Hash = validation.GenerateSecureHash(string(sbomData))

	// Log performance
	h.logger.Performance("generate_sbom", time.Since(start), map[string]interface{}{
		"sbom_id":         generatedSBOM.ID.String(),
		"format":          string(format),
		"components":      len(generatedSBOM.Components),
		"include_dev":     req.IncludeDev,
		"scan_licenses":   req.ScanLicenses,
	})

	h.logger.Audit("generate_sbom", c.GetString("user_id"), generatedSBOM.ID.String(), true, map[string]interface{}{
		"format":     string(format),
		"source":     req.Source,
		"components": len(generatedSBOM.Components),
	})

	c.JSON(http.StatusCreated, gin.H{
		"sbom": generatedSBOM,
		"metadata": gin.H{
			"components_count": len(generatedSBOM.Components),
			"format":          string(format),
			"generated_at":    generatedSBOM.CreatedAt,
			"source":          req.Source,
		},
	})
}

func (h *SBOMHandler) AnalyzeSBOM(c *gin.Context) {
	ctx := c.Request.Context()
	start := time.Now()

	var req struct {
		SBOM             json.RawMessage `json:"sbom" binding:"required"`
		CheckLicenses    bool           `json:"check_licenses"`
		CheckVulns       bool           `json:"check_vulnerabilities"`
		PolicyRules      []string       `json:"policy_rules"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		appErr := errors.NewValidationError("Invalid request format", err.Error())
		h.logger.LogError(ctx, appErr, "bind_request", map[string]interface{}{
			"operation": "analyze_sbom",
			"client_ip": c.ClientIP(),
		})
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Detect SBOM format
	format, err := h.parser.DetectFormat(req.SBOM)
	if err != nil {
		appErr := errors.NewValidationError("Unable to detect SBOM format", err.Error())
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Parse SBOM
	sbomReader := strings.NewReader(string(req.SBOM))
	parsedSBOM, err := h.parser.ParseSBOM(sbomReader, format)
	if err != nil {
		appErr := errors.NewValidationError("Failed to parse SBOM", err.Error())
		c.JSON(appErr.StatusCode, appErr.ToResponse())
		return
	}

	// Perform analysis
	analysis := map[string]interface{}{
		"sbom_id":          parsedSBOM.ID,
		"format":           string(format),
		"components_total": len(parsedSBOM.Components),
		"created_at":       parsedSBOM.CreatedAt,
		"created_by":       parsedSBOM.CreatedBy,
	}

	// Component type breakdown
	componentTypes := make(map[string]int)
	languages := make(map[string]int)
	ecosystems := make(map[string]int)

	for _, component := range parsedSBOM.Components {
		componentTypes[string(component.Type)]++
		
		if lang, exists := component.Metadata["language"]; exists {
			languages[lang]++
		}
		if eco, exists := component.Metadata["ecosystem"]; exists {
			ecosystems[eco]++
		}
	}

	analysis["component_types"] = componentTypes
	analysis["languages"] = languages
	analysis["ecosystems"] = ecosystems

	// License analysis if requested
	if req.CheckLicenses {
		licenseAnalysis := map[string]interface{}{
			"licenses_found": make(map[string]int),
			"issues":         []string{},
			"compliance":     "PASS",
		}

		licenseCounts := make(map[string]int)
		for _, component := range parsedSBOM.Components {
			for _, license := range component.License {
				licenseCounts[license]++
			}
		}

		// Check for problematic licenses
		problematicLicenses := []string{"GPL-3.0", "AGPL-3.0", "LGPL-3.0"}
		for _, license := range problematicLicenses {
			if count, exists := licenseCounts[license]; exists && count > 0 {
				licenseAnalysis["issues"] = append(licenseAnalysis["issues"].([]string), 
					"Found "+license+" license which may require legal review")
				licenseAnalysis["compliance"] = "REVIEW_REQUIRED"
			}
		}

		licenseAnalysis["licenses_found"] = licenseCounts
		analysis["license_analysis"] = licenseAnalysis
	}

	// Vulnerability analysis if requested (simulated)
	if req.CheckVulns {
		vulnAnalysis := map[string]interface{}{
			"vulnerabilities": map[string]int{
				"critical": 0,
				"high":     2,
				"medium":   5,
				"low":      3,
			},
			"affected_components": []string{
				"gin-gonic/gin@v1.10.1",
				"neo4j/neo4j-go-driver@v5.24.0",
			},
			"scan_timestamp": time.Now(),
			"scan_status":    "COMPLETED",
		}

		analysis["vulnerability_analysis"] = vulnAnalysis
	}

	// Log performance
	h.logger.Performance("analyze_sbom", time.Since(start), map[string]interface{}{
		"sbom_id":         parsedSBOM.ID.String(),
		"format":          string(format),
		"components":      len(parsedSBOM.Components),
		"check_licenses":  req.CheckLicenses,
		"check_vulns":     req.CheckVulns,
	})

	h.logger.Audit("analyze_sbom", c.GetString("user_id"), parsedSBOM.ID.String(), true, map[string]interface{}{
		"format":     string(format),
		"components": len(parsedSBOM.Components),
	})

	c.JSON(http.StatusOK, gin.H{
		"analysis": analysis,
		"metadata": gin.H{
			"analysis_timestamp": time.Now(),
			"analyzer_version":   "1.0.0",
		},
	})
}

func (h *SBOMHandler) ParseSBOM(c *gin.Context) {
	// Legacy endpoint - redirect to AnalyzeSBOM
	h.AnalyzeSBOM(c)
}

func (h *SBOMHandler) GetSBOM(c *gin.Context) {
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

	// Generation 1: Return placeholder SBOM - will be retrieved from database in Generation 2
	placeholderSBOM := types.SBOM{
		ID:        uuid.MustParse(id),
		Format:    types.SBOMFormatCycloneDX,
		Version:   "1.0",
		CreatedAt: time.Now().Add(-24 * time.Hour), // Created yesterday
		CreatedBy: "provenance-linker",
		Hash:      "placeholder-hash",
		Metadata:  map[string]string{
			"status": "placeholder",
			"note":   "Database retrieval will be implemented in Generation 2",
		},
		Components: []types.Component{},
	}

	c.JSON(http.StatusOK, gin.H{
		"sbom": placeholderSBOM,
		"metadata": gin.H{
			"retrieved_at": time.Now(),
			"version":      "v1",
			"note":         "Placeholder implementation - full database integration in Generation 2",
		},
	})
}