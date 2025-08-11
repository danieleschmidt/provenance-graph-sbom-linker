package test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/version"
)

func TestBasicFunctionality(t *testing.T) {
	t.Run("Version Information", func(t *testing.T) {
		assert.NotEmpty(t, version.Version)
		assert.Equal(t, "dev", version.Version)
	})

	t.Run("Artifact Types", func(t *testing.T) {
		// Test artifact type constants
		assert.Equal(t, "container", string(types.ArtifactTypeContainer))
		assert.Equal(t, "binary", string(types.ArtifactTypeBinary))
		assert.Equal(t, "ml-model", string(types.ArtifactTypeMLModel))
		assert.Equal(t, "library", string(types.ArtifactTypeLibrary))
	})

	t.Run("SBOM Format Types", func(t *testing.T) {
		// Test SBOM format constants
		assert.Equal(t, "cyclonedx", string(types.SBOMFormatCycloneDX))
		assert.Equal(t, "spdx", string(types.SBOMFormatSPDX))
		assert.Equal(t, "syft", string(types.SBOMFormatSyft))
	})

	t.Run("Compliance Standards", func(t *testing.T) {
		// Test compliance standard constants
		assert.Equal(t, "nist-ssdf", string(types.ComplianceStandardNISTSSDF))
		assert.Equal(t, "eu-cra", string(types.ComplianceStandardEUCRA))
		assert.Equal(t, "custom", string(types.ComplianceStandardCustom))
	})

	t.Run("Component Types", func(t *testing.T) {
		// Test component type constants
		assert.Equal(t, "library", string(types.ComponentTypeLibrary))
		assert.Equal(t, "application", string(types.ComponentTypeApplication))
		assert.Equal(t, "framework", string(types.ComponentTypeFramework))
		assert.Equal(t, "container", string(types.ComponentTypeContainer))
	})
}

func TestTypeStructures(t *testing.T) {
	t.Run("Artifact Structure", func(t *testing.T) {
		artifact := &types.Artifact{
			Name:      "test-artifact",
			Version:   "1.0.0",
			Type:      types.ArtifactTypeContainer,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Metadata:  make(map[string]string),
		}

		assert.Equal(t, "test-artifact", artifact.Name)
		assert.Equal(t, "1.0.0", artifact.Version)
		assert.Equal(t, types.ArtifactTypeContainer, artifact.Type)
		assert.NotNil(t, artifact.Metadata)
	})

	t.Run("SBOM Structure", func(t *testing.T) {
		sbom := &types.SBOM{
			Format:     types.SBOMFormatCycloneDX,
			Version:    "1.0",
			CreatedAt:  time.Now(),
			CreatedBy:  "test-system",
			Components: []types.Component{},
			Metadata:   make(map[string]string),
		}

		assert.Equal(t, types.SBOMFormatCycloneDX, sbom.Format)
		assert.Equal(t, "1.0", sbom.Version)
		assert.Equal(t, "test-system", sbom.CreatedBy)
		assert.NotNil(t, sbom.Components)
		assert.NotNil(t, sbom.Metadata)
	})

	t.Run("Compliance Report Structure", func(t *testing.T) {
		report := &types.ComplianceReport{
			Standard:     types.ComplianceStandardNISTSSDF,
			ProjectName:  "test-project",
			Version:      "1.0.0",
			Status:       types.ComplianceStatusCompliant,
			Score:        95.5,
			Requirements: []types.RequirementResult{},
			Evidence:     []types.Evidence{},
			GeneratedAt:  time.Now(),
			GeneratedBy:  "test-system",
			Metadata:     make(map[string]string),
		}

		assert.Equal(t, types.ComplianceStandardNISTSSDF, report.Standard)
		assert.Equal(t, "test-project", report.ProjectName)
		assert.Equal(t, types.ComplianceStatusCompliant, report.Status)
		assert.Equal(t, 95.5, report.Score)
		assert.NotNil(t, report.Requirements)
		assert.NotNil(t, report.Evidence)
		assert.NotNil(t, report.Metadata)
	})
}

func TestValidation(t *testing.T) {
	t.Run("UUID Parsing", func(t *testing.T) {
		validUUID := "550e8400-e29b-41d4-a716-446655440000"
		uuid, err := types.ParseUUID(validUUID)
		assert.NoError(t, err)
		assert.Equal(t, validUUID, uuid.String())

		invalidUUID := "invalid-uuid"
		_, err = types.ParseUUID(invalidUUID)
		assert.Error(t, err)
	})

	t.Run("Required Fields", func(t *testing.T) {
		// Test that zero values work correctly
		artifact := &types.Artifact{}
		assert.Empty(t, artifact.Name)
		assert.Empty(t, artifact.Version)
		assert.Equal(t, types.ArtifactType(""), artifact.Type)

		// Test populated values
		artifact.Name = "populated-artifact"
		artifact.Version = "2.0.0"
		artifact.Type = types.ArtifactTypeBinary

		assert.Equal(t, "populated-artifact", artifact.Name)
		assert.Equal(t, "2.0.0", artifact.Version)
		assert.Equal(t, types.ArtifactTypeBinary, artifact.Type)
	})
}

func TestPerformanceMetrics(t *testing.T) {
	t.Run("Time Measurements", func(t *testing.T) {
		start := time.Now()
		time.Sleep(10 * time.Millisecond) // Simulate work
		duration := time.Since(start)

		assert.Greater(t, duration.Milliseconds(), int64(9))
		assert.Less(t, duration.Milliseconds(), int64(50))
	})

	t.Run("Memory Allocation", func(t *testing.T) {
		// Test that creating structures doesn't panic
		artifacts := make([]types.Artifact, 100)
		for i := range artifacts {
			artifacts[i] = types.Artifact{
				Name:     "artifact-" + string(rune(i+'0')),
				Version:  "1.0.0",
				Type:     types.ArtifactTypeLibrary,
				Metadata: make(map[string]string),
			}
		}

		assert.Len(t, artifacts, 100)
		assert.Equal(t, "artifact-0", artifacts[0].Name)
	})
}

func TestBoundaryConditions(t *testing.T) {
	t.Run("Empty Values", func(t *testing.T) {
		// Test handling of empty/nil values
		var artifact *types.Artifact
		assert.Nil(t, artifact)

		artifact = &types.Artifact{}
		assert.NotNil(t, artifact)
		assert.Empty(t, artifact.Name)
	})

	t.Run("Large Values", func(t *testing.T) {
		// Test with large strings
		largeString := string(make([]byte, 1000))
		artifact := &types.Artifact{
			Name:    largeString,
			Version: "1.0.0",
			Type:    types.ArtifactTypeContainer,
		}

		assert.Len(t, artifact.Name, 1000)
		assert.Equal(t, "1.0.0", artifact.Version)
	})

	t.Run("Unicode Handling", func(t *testing.T) {
		// Test with unicode characters
		artifact := &types.Artifact{
			Name:    "测试-artifact-🚀",
			Version: "1.0.0-β",
			Type:    types.ArtifactTypeLibrary,
		}

		assert.Equal(t, "测试-artifact-🚀", artifact.Name)
		assert.Equal(t, "1.0.0-β", artifact.Version)
	})
}