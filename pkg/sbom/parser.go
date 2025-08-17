package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

// Parser handles parsing various SBOM formats
type Parser struct{}

// NewParser creates a new SBOM parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseSBOM parses an SBOM from the provided reader and format
func (p *Parser) ParseSBOM(reader io.Reader, format types.SBOMFormat) (*types.SBOM, error) {
	switch format {
	case types.SBOMFormatCycloneDX:
		return p.parseCycloneDX(reader)
	case types.SBOMFormatSPDX:
		return p.parseSPDX(reader)
	case types.SBOMFormatSyft:
		return p.parseSyft(reader)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}

// DetectFormat attempts to detect the SBOM format from the content
func (p *Parser) DetectFormat(data []byte) (types.SBOMFormat, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", fmt.Errorf("invalid JSON format: %w", err)
	}

	// CycloneDX detection
	if bomFormat, exists := raw["bomFormat"]; exists {
		if bomFormat == "CycloneDX" {
			return types.SBOMFormatCycloneDX, nil
		}
	}

	// SPDX detection
	if spdxID, exists := raw["spdxVersion"]; exists {
		if spdxID != nil {
			return types.SBOMFormatSPDX, nil
		}
	}

	// Syft detection
	if descriptor, exists := raw["descriptor"]; exists {
		if desc, ok := descriptor.(map[string]interface{}); ok {
			if name, exists := desc["name"]; exists && name == "syft" {
				return types.SBOMFormatSyft, nil
			}
		}
	}

	return "", fmt.Errorf("unable to detect SBOM format")
}

// ParseCycloneDX parses CycloneDX format SBOM from data
func (p *Parser) ParseCycloneDX(data []byte) (*types.SBOM, error) {
	var cycloneDX struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Version     int    `json:"version"`
		Metadata    struct {
			Timestamp string `json:"timestamp"`
			Tools     []struct {
				Vendor  string `json:"vendor"`
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"tools"`
		} `json:"metadata"`
		Components []struct {
			Type        string `json:"type"`
			BomRef      string `json:"bom-ref"`
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
			Licenses    []struct {
				License struct {
					Name string `json:"name"`
					ID   string `json:"id"`
				} `json:"license"`
			} `json:"licenses"`
			Purl     string `json:"purl"`
			Hashes   []struct {
				Alg     string `json:"alg"`
				Content string `json:"content"`
			} `json:"hashes"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(data, &cycloneDX); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX SBOM: %w", err)
	}

	// Parse timestamp
	createdAt := time.Now()
	if cycloneDX.Metadata.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, cycloneDX.Metadata.Timestamp); err == nil {
			createdAt = parsed
		}
	}

	// Convert components
	components := make([]types.Component, 0, len(cycloneDX.Components))
	for _, comp := range cycloneDX.Components {
		licenses := make([]string, 0, len(comp.Licenses))
		for _, license := range comp.Licenses {
			if license.License.ID != "" {
				licenses = append(licenses, license.License.ID)
			} else if license.License.Name != "" {
				licenses = append(licenses, license.License.Name)
			}
		}

		hash := ""
		if len(comp.Hashes) > 0 {
			hash = comp.Hashes[0].Content
		}

		componentType := types.ComponentTypeLibrary
		switch comp.Type {
		case "application":
			componentType = types.ComponentTypeApplication
		case "framework":
			componentType = types.ComponentTypeFramework
		case "library":
			componentType = types.ComponentTypeLibrary
		case "container":
			componentType = types.ComponentTypeContainer
		case "file":
			componentType = types.ComponentTypeFile
		case "operating-system":
			componentType = types.ComponentTypeOS
		}

		components = append(components, types.Component{
			ID:          uuid.New(),
			Name:        comp.Name,
			Version:     comp.Version,
			Type:        componentType,
			License:     licenses,
			Hash:        hash,
			Description: comp.Description,
			Metadata: map[string]string{
				"bom-ref": comp.BomRef,
				"purl":    comp.Purl,
			},
		})
	}

	// Parse created by info
	createdBy := "unknown"
	if len(cycloneDX.Metadata.Tools) > 0 {
		tool := cycloneDX.Metadata.Tools[0]
		createdBy = fmt.Sprintf("%s %s %s", tool.Vendor, tool.Name, tool.Version)
		createdBy = strings.TrimSpace(createdBy)
	}

	return &types.SBOM{
		ID:         uuid.New(),
		Format:     types.SBOMFormatCycloneDX,
		Version:    cycloneDX.SpecVersion,
		CreatedAt:  createdAt,
		CreatedBy:  createdBy,
		Components: components,
		Metadata: map[string]string{
			"serial_number": cycloneDX.SerialNumber,
			"version":       fmt.Sprintf("%d", cycloneDX.Version),
			"format":        cycloneDX.BOMFormat,
		},
		Serialized: data,
	}, nil
}

// parseCycloneDX parses CycloneDX format SBOM
func (p *Parser) parseCycloneDX(reader io.Reader) (*types.SBOM, error) {
	var cycloneDX struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Version     int    `json:"version"`
		Metadata    struct {
			Timestamp string `json:"timestamp"`
			Tools     []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"tools"`
		} `json:"metadata"`
		Components []struct {
			Type        string   `json:"type"`
			BomRef      string   `json:"bom-ref"`
			Name        string   `json:"name"`
			Version     string   `json:"version"`
			Licenses    []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
			Description string `json:"description"`
			Hashes      []struct {
				Algorithm string `json:"alg"`
				Content   string `json:"content"`
			} `json:"hashes"`
			ExternalReferences []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"externalReferences"`
		} `json:"components"`
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM data: %w", err)
	}

	if err := json.Unmarshal(data, &cycloneDX); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX SBOM: %w", err)
	}

	sbom := &types.SBOM{
		ID:        uuid.New(),
		Format:    types.SBOMFormatCycloneDX,
		Version:   cycloneDX.SpecVersion,
		CreatedAt: time.Now(),
		CreatedBy: "cyclonedx-parser",
		Metadata:  make(map[string]string),
	}

	// Parse timestamp if available
	if cycloneDX.Metadata.Timestamp != "" {
		if timestamp, err := time.Parse(time.RFC3339, cycloneDX.Metadata.Timestamp); err == nil {
			sbom.CreatedAt = timestamp
		}
	}

	// Parse tool information
	if len(cycloneDX.Metadata.Tools) > 0 {
		sbom.CreatedBy = cycloneDX.Metadata.Tools[0].Name
		if cycloneDX.Metadata.Tools[0].Version != "" {
			sbom.CreatedBy += ":" + cycloneDX.Metadata.Tools[0].Version
		}
	}

	// Parse components
	for _, comp := range cycloneDX.Components {
		component := types.Component{
			ID:          uuid.New(),
			Name:        comp.Name,
			Version:     comp.Version,
			Type:        mapCycloneDXComponentType(comp.Type),
			Description: comp.Description,
			License:     extractLicenses(comp.Licenses),
			Metadata:    make(map[string]string),
		}

		// Add hashes to metadata
		for _, hash := range comp.Hashes {
			component.Metadata[hash.Algorithm] = hash.Content
		}

		// Add external references
		for _, ref := range comp.ExternalReferences {
			if ref.Type == "website" {
				component.Homepage = ref.URL
			}
		}

		sbom.Components = append(sbom.Components, component)
	}

	return sbom, nil
}

// parseSPDX parses SPDX format SBOM
func (p *Parser) parseSPDX(reader io.Reader) (*types.SBOM, error) {
	var spdx struct {
		SPDXVersion     string `json:"spdxVersion"`
		SPDXDataLicense string `json:"dataLicense"`
		SPDXID          string `json:"SPDXID"`
		Name            string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		CreationInfo    struct {
			Created string   `json:"created"`
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Packages []struct {
			SPDXID               string   `json:"SPDXID"`
			Name                 string   `json:"name"`
			VersionInfo          string   `json:"versionInfo"`
			DownloadLocation     string   `json:"downloadLocation"`
			FilesAnalyzed        bool     `json:"filesAnalyzed"`
			LicenseConcluded     string   `json:"licenseConcluded"`
			LicenseDeclared      string   `json:"licenseDeclared"`
			CopyrightText        string   `json:"copyrightText"`
			ExternalRefs         []struct {
				ReferenceCategory string `json:"referenceCategory"`
				ReferenceType     string `json:"referenceType"`
				ReferenceLocator  string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM data: %w", err)
	}

	if err := json.Unmarshal(data, &spdx); err != nil {
		return nil, fmt.Errorf("failed to parse SPDX SBOM: %w", err)
	}

	sbom := &types.SBOM{
		ID:        uuid.New(),
		Format:    types.SBOMFormatSPDX,
		Version:   spdx.SPDXVersion,
		CreatedAt: time.Now(),
		CreatedBy: "spdx-parser",
		Metadata:  make(map[string]string),
	}

	// Parse creation info
	if spdx.CreationInfo.Created != "" {
		if timestamp, err := time.Parse(time.RFC3339, spdx.CreationInfo.Created); err == nil {
			sbom.CreatedAt = timestamp
		}
	}

	if len(spdx.CreationInfo.Creators) > 0 {
		sbom.CreatedBy = spdx.CreationInfo.Creators[0]
	}

	// Parse packages as components
	for _, pkg := range spdx.Packages {
		component := types.Component{
			ID:       uuid.New(),
			Name:     pkg.Name,
			Version:  pkg.VersionInfo,
			Type:     types.ComponentTypeLibrary, // Default for SPDX packages
			License:  extractSPDXLicenses(pkg.LicenseConcluded, pkg.LicenseDeclared),
			Metadata: make(map[string]string),
		}

		// Add download location if available
		if pkg.DownloadLocation != "" && pkg.DownloadLocation != "NOASSERTION" {
			component.Homepage = pkg.DownloadLocation
		}

		// Add external references to metadata
		for _, ref := range pkg.ExternalRefs {
			component.Metadata[ref.ReferenceType] = ref.ReferenceLocator
		}

		sbom.Components = append(sbom.Components, component)
	}

	return sbom, nil
}

// parseSyft parses Syft format SBOM
func (p *Parser) parseSyft(reader io.Reader) (*types.SBOM, error) {
	var syft struct {
		Artifacts []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			FoundBy   string `json:"foundBy"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
			Licenses []struct {
				Value          string   `json:"value"`
				SPDXExpression string   `json:"spdxExpression"`
				Type           string   `json:"type"`
				URLs           []string `json:"urls"`
			} `json:"licenses"`
			Language     string `json:"language"`
			MetadataType string `json:"metadataType"`
			Metadata     map[string]interface{} `json:"metadata"`
		} `json:"artifacts"`
		ArtifactRelationships []struct {
			Parent string `json:"parent"`
			Child  string `json:"child"`
			Type   string `json:"type"`
		} `json:"artifactRelationships"`
		Descriptor struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"descriptor"`
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM data: %w", err)
	}

	if err := json.Unmarshal(data, &syft); err != nil {
		return nil, fmt.Errorf("failed to parse Syft SBOM: %w", err)
	}

	sbom := &types.SBOM{
		ID:        uuid.New(),
		Format:    types.SBOMFormatSyft,
		Version:   "1.0",
		CreatedAt: time.Now(),
		CreatedBy: syft.Descriptor.Name + ":" + syft.Descriptor.Version,
		Metadata:  make(map[string]string),
	}

	// Parse artifacts as components
	for _, artifact := range syft.Artifacts {
		component := types.Component{
			ID:       uuid.New(),
			Name:     artifact.Name,
			Version:  artifact.Version,
			Type:     mapSyftComponentType(artifact.Type),
			License:  extractSyftLicenses(artifact.Licenses),
			Metadata: make(map[string]string),
		}

		// Add language and metadata type
		if artifact.Language != "" {
			component.Metadata["language"] = artifact.Language
		}
		if artifact.MetadataType != "" {
			component.Metadata["type"] = artifact.MetadataType
		}

		// Add locations
		for i, location := range artifact.Locations {
			component.Metadata[fmt.Sprintf("location_%d", i)] = location.Path
		}

		sbom.Components = append(sbom.Components, component)
	}

	return sbom, nil
}

// Helper functions for mapping component types and extracting licenses

func mapCycloneDXComponentType(cycloneDXType string) types.ComponentType {
	switch cycloneDXType {
	case "application":
		return types.ComponentTypeApplication
	case "framework":
		return types.ComponentTypeFramework
	case "library":
		return types.ComponentTypeLibrary
	case "container":
		return types.ComponentTypeContainer
	case "operating-system":
		return types.ComponentTypeOS
	case "device":
		return types.ComponentTypeDevice
	case "firmware":
		return types.ComponentTypeFirmware
	case "file":
		return types.ComponentTypeFile
	default:
		return types.ComponentTypeLibrary
	}
}

func mapSyftComponentType(syftType string) types.ComponentType {
	switch syftType {
	case "go-module", "java-archive", "python-package", "npm-package":
		return types.ComponentTypeLibrary
	case "binary":
		return types.ComponentTypeApplication
	default:
		return types.ComponentTypeLibrary
	}
}

func extractLicenses(licenses []struct {
	License struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
}) []string {
	var result []string
	for _, license := range licenses {
		if license.License.ID != "" {
			result = append(result, license.License.ID)
		} else if license.License.Name != "" {
			result = append(result, license.License.Name)
		}
	}
	return result
}

func extractSPDXLicenses(concluded, declared string) []string {
	var licenses []string
	if concluded != "" && concluded != "NOASSERTION" && concluded != "NONE" {
		licenses = append(licenses, concluded)
	}
	if declared != "" && declared != "NOASSERTION" && declared != "NONE" && declared != concluded {
		licenses = append(licenses, declared)
	}
	return licenses
}

func extractSyftLicenses(licenses []struct {
	Value          string   `json:"value"`
	SPDXExpression string   `json:"spdxExpression"`
	Type           string   `json:"type"`
	URLs           []string `json:"urls"`
}) []string {
	var result []string
	for _, license := range licenses {
		if license.SPDXExpression != "" {
			result = append(result, license.SPDXExpression)
		} else if license.Value != "" {
			result = append(result, license.Value)
		}
	}
	return result
}