package sbom

import (
	"strings"
	"testing"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

func TestParser_DetectFormat(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		input    string
		expected types.SBOMFormat
		hasError bool
	}{
		{
			name: "CycloneDX format",
			input: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4",
				"components": []
			}`,
			expected: types.SBOMFormatCycloneDX,
			hasError: false,
		},
		{
			name: "SPDX format",
			input: `{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"packages": []
			}`,
			expected: types.SBOMFormatSPDX,
			hasError: false,
		},
		{
			name: "Syft format",
			input: `{
				"descriptor": {
					"name": "syft",
					"version": "0.82.0"
				},
				"artifacts": []
			}`,
			expected: types.SBOMFormatSyft,
			hasError: false,
		},
		{
			name: "Unknown format",
			input: `{
				"unknown": "format",
				"data": []
			}`,
			expected: "",
			hasError: true,
		},
		{
			name: "Invalid JSON",
			input: `{invalid json`,
			expected: "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, err := parser.DetectFormat([]byte(tt.input))
			
			if tt.hasError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if format != tt.expected {
				t.Errorf("Expected format %v, got %v", tt.expected, format)
			}
		})
	}
}

func TestParser_ParseCycloneDX(t *testing.T) {
	parser := NewParser()
	
	cycloneDXData := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"serialNumber": "urn:uuid:test-123",
		"version": 1,
		"metadata": {
			"timestamp": "2023-01-01T12:00:00Z",
			"tools": [{
				"vendor": "Test Vendor",
				"name": "test-tool",
				"version": "1.0.0"
			}]
		},
		"components": [{
			"type": "library",
			"bom-ref": "test-component",
			"name": "test-library",
			"version": "1.0.0",
			"description": "Test library",
			"licenses": [{
				"license": {
					"id": "MIT"
				}
			}],
			"hashes": [{
				"alg": "SHA-256",
				"content": "abc123"
			}]
		}]
	}`

	sbom, err := parser.ParseCycloneDX([]byte(cycloneDXData))
	if err != nil {
		t.Fatalf("Failed to parse CycloneDX SBOM: %v", err)
	}

	// Verify SBOM metadata
	if sbom.Format != types.SBOMFormatCycloneDX {
		t.Errorf("Expected format %v, got %v", types.SBOMFormatCycloneDX, sbom.Format)
	}

	if sbom.Version != "1.4" {
		t.Errorf("Expected version 1.4, got %v", sbom.Version)
	}

	if sbom.CreatedBy != "Test Vendor test-tool 1.0.0" {
		t.Errorf("Expected creator 'Test Vendor test-tool 1.0.0', got %v", sbom.CreatedBy)
	}

	// Verify timestamp parsing
	expectedTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	if !sbom.CreatedAt.Equal(expectedTime) {
		t.Errorf("Expected timestamp %v, got %v", expectedTime, sbom.CreatedAt)
	}

	// Verify components
	if len(sbom.Components) != 1 {
		t.Fatalf("Expected 1 component, got %d", len(sbom.Components))
	}

	component := sbom.Components[0]
	if component.Name != "test-library" {
		t.Errorf("Expected component name 'test-library', got %v", component.Name)
	}

	if component.Version != "1.0.0" {
		t.Errorf("Expected component version '1.0.0', got %v", component.Version)
	}

	if component.Type != types.ComponentTypeLibrary {
		t.Errorf("Expected component type %v, got %v", types.ComponentTypeLibrary, component.Type)
	}

	if len(component.License) != 1 || component.License[0] != "MIT" {
		t.Errorf("Expected license [MIT], got %v", component.License)
	}

	if component.Hash != "abc123" {
		t.Errorf("Expected hash 'abc123', got %v", component.Hash)
	}
}

func TestParser_ParseSBOM(t *testing.T) {
	parser := NewParser()

	cycloneDXData := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": []
	}`

	sbom, err := parser.ParseSBOM(strings.NewReader(cycloneDXData), types.SBOMFormatCycloneDX)
	if err != nil {
		t.Fatalf("Failed to parse SBOM: %v", err)
	}

	if sbom.Format != types.SBOMFormatCycloneDX {
		t.Errorf("Expected format %v, got %v", types.SBOMFormatCycloneDX, sbom.Format)
	}

	// Test unsupported format
	_, err = parser.ParseSBOM(strings.NewReader("{}"), "unsupported")
	if err == nil {
		t.Error("Expected error for unsupported format")
	}
}

func TestComponentTypeMapping(t *testing.T) {
	tests := []struct {
		cycloneDXType string
		expected      types.ComponentType
	}{
		{"application", types.ComponentTypeApplication},
		{"framework", types.ComponentTypeFramework},
		{"library", types.ComponentTypeLibrary},
		{"container", types.ComponentTypeContainer},
		{"operating-system", types.ComponentTypeOS},
		{"device", types.ComponentTypeDevice},
		{"firmware", types.ComponentTypeFirmware},
		{"file", types.ComponentTypeFile},
		{"unknown", types.ComponentTypeLibrary}, // default
	}

	for _, tt := range tests {
		t.Run(tt.cycloneDXType, func(t *testing.T) {
			result := mapCycloneDXComponentType(tt.cycloneDXType)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSyftComponentTypeMapping(t *testing.T) {
	tests := []struct {
		syftType string
		expected types.ComponentType
	}{
		{"go-module", types.ComponentTypeLibrary},
		{"java-archive", types.ComponentTypeLibrary},
		{"python-package", types.ComponentTypeLibrary},
		{"npm-package", types.ComponentTypeLibrary},
		{"binary", types.ComponentTypeApplication},
		{"unknown", types.ComponentTypeLibrary}, // default
	}

	for _, tt := range tests {
		t.Run(tt.syftType, func(t *testing.T) {
			result := mapSyftComponentType(tt.syftType)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestLicenseExtraction(t *testing.T) {
	tests := []struct {
		name      string
		licenses  []struct {
			License struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"license"`
		}
		expected []string
	}{
		{
			name: "ID only",
			licenses: []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			}{
				{License: struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				}{ID: "MIT", Name: ""}},
			},
			expected: []string{"MIT"},
		},
		{
			name: "Name only",
			licenses: []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			}{
				{License: struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				}{ID: "", Name: "MIT License"}},
			},
			expected: []string{"MIT License"},
		},
		{
			name: "Both ID and Name",
			licenses: []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			}{
				{License: struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				}{ID: "MIT", Name: "MIT License"}},
			},
			expected: []string{"MIT"}, // ID takes precedence
		},
		{
			name:      "Empty",
			licenses:  []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			}{},
			expected:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractLicenses(tt.licenses)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d licenses, got %d", len(tt.expected), len(result))
				return
			}

			for i, license := range result {
				if license != tt.expected[i] {
					t.Errorf("Expected license %v, got %v", tt.expected[i], license)
				}
			}
		})
	}
}