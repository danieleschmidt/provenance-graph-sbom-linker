package validation

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

func TestValidator_ValidateArtifact(t *testing.T) {
	tests := []struct {
		name         string
		artifact     *types.Artifact
		expectErrors []string
	}{
		{
			name: "Valid artifact",
			artifact: &types.Artifact{
				ID:       uuid.New(),
				Name:     "valid-artifact",
				Version:  "1.0.0",
				Type:     types.ArtifactTypeContainer,
				Hash:     "sha256:abcdef123456789012345678901234567890abcdef123456789012345678901234",
				Size:     1024,
				Metadata: map[string]string{"env": "test"},
			},
			expectErrors: []string{},
		},
		{
			name:         "Nil artifact",
			artifact:     nil,
			expectErrors: []string{"artifact cannot be nil"},
		},
		{
			name: "Empty name",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    "",
				Version: "1.0.0",
				Type:    types.ArtifactTypeContainer,
			},
			expectErrors: []string{"name is required"},
		},
		{
			name: "Name too long",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    string(make([]byte, 256)),
				Version: "1.0.0",
				Type:    types.ArtifactTypeContainer,
			},
			expectErrors: []string{"name cannot exceed 255 characters"},
		},
		{
			name: "Invalid name characters",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    "invalid@name!",
				Version: "1.0.0",
				Type:    types.ArtifactTypeContainer,
			},
			expectErrors: []string{"name contains invalid characters"},
		},
		{
			name: "Empty version",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    "test-artifact",
				Version: "",
				Type:    types.ArtifactTypeContainer,
			},
			expectErrors: []string{"version is required"},
		},
		{
			name: "Invalid version format",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    "test-artifact",
				Version: "1.0..0",
				Type:    types.ArtifactTypeContainer,
			},
			expectErrors: []string{"version format is invalid"},
		},
		{
			name: "Empty type",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    "test-artifact",
				Version: "1.0.0",
				Type:    "",
			},
			expectErrors: []string{"type is required"},
		},
		{
			name: "Invalid artifact type",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    "test-artifact",
				Version: "1.0.0",
				Type:    types.ArtifactType("invalid"),
			},
			expectErrors: []string{"invalid artifact type"},
		},
		{
			name: "Invalid hash format",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    "test-artifact",
				Version: "1.0.0",
				Type:    types.ArtifactTypeContainer,
				Hash:    "invalid-hash",
			},
			expectErrors: []string{"hash format is invalid"},
		},
		{
			name: "Negative size",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    "test-artifact",
				Version: "1.0.0",
				Type:    types.ArtifactTypeContainer,
				Size:    -100,
			},
			expectErrors: []string{"size cannot be negative"},
		},
		{
			name: "Size too large",
			artifact: &types.Artifact{
				ID:      uuid.New(),
				Name:    "test-artifact",
				Version: "1.0.0",
				Type:    types.ArtifactTypeContainer,
				Size:    11 * 1024 * 1024 * 1024,
			},
			expectErrors: []string{"size cannot exceed 10GB"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewValidator()
			validator.ValidateArtifact(tt.artifact)

			if len(tt.expectErrors) == 0 {
				assert.False(t, validator.HasErrors(), "Expected no validation errors")
			} else {
				assert.True(t, validator.HasErrors(), "Expected validation errors")
				errors := validator.GetErrors()
				
				for _, expectedError := range tt.expectErrors {
					found := false
					for _, actualError := range errors {
						if actualError.Message == expectedError {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error message not found: %s", expectedError)
				}
			}
		})
	}
}

func TestValidator_ValidateSource(t *testing.T) {
	tests := []struct {
		name         string
		source       *types.Source
		expectErrors []string
	}{
		{
			name: "Valid git source",
			source: &types.Source{
				ID:         uuid.New(),
				Type:       types.SourceTypeGit,
				URL:        "https://github.com/user/repo.git",
				Branch:     "main",
				CommitHash: "abcdef1234567890abcdef1234567890abcdef12",
				Metadata:   map[string]string{},
			},
			expectErrors: []string{},
		},
		{
			name:         "Nil source",
			source:       nil,
			expectErrors: []string{"source cannot be nil"},
		},
		{
			name: "Empty URL",
			source: &types.Source{
				Type: types.SourceTypeGit,
				URL:  "",
			},
			expectErrors: []string{"url is required"},
		},
		{
			name: "Invalid URL format",
			source: &types.Source{
				Type: types.SourceTypeGit,
				URL:  "not-a-url",
			},
			expectErrors: []string{"url format is invalid"},
		},
		{
			name: "Invalid commit hash",
			source: &types.Source{
				Type:       types.SourceTypeGit,
				URL:        "https://github.com/user/repo.git",
				CommitHash: "invalid-hash",
			},
			expectErrors: []string{"commit hash format is invalid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewValidator()
			validator.ValidateSource(tt.source)

			if len(tt.expectErrors) == 0 {
				assert.False(t, validator.HasErrors())
			} else {
				assert.True(t, validator.HasErrors())
				errors := validator.GetErrors()
				
				for _, expectedError := range tt.expectErrors {
					found := false
					for _, actualError := range errors {
						if actualError.Message == expectedError {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error message not found: %s", expectedError)
				}
			}
		})
	}
}

func TestValidator_ValidateSBOM(t *testing.T) {
	validComponent := types.Component{
		ID:      uuid.New(),
		Name:    "test-component",
		Version: "1.0.0",
		Type:    types.ComponentTypeLibrary,
		License: []string{"MIT"},
		Metadata: map[string]string{},
	}

	tests := []struct {
		name         string
		sbom         *types.SBOM
		expectErrors []string
	}{
		{
			name: "Valid SBOM",
			sbom: &types.SBOM{
				ID:         uuid.New(),
				Format:     types.SBOMFormatCycloneDX,
				Version:    "1.0",
				CreatedBy:  "test-system",
				Components: []types.Component{validComponent},
				Metadata:   map[string]string{},
			},
			expectErrors: []string{},
		},
		{
			name:         "Nil SBOM",
			sbom:         nil,
			expectErrors: []string{"sbom cannot be nil"},
		},
		{
			name: "Empty format",
			sbom: &types.SBOM{
				Format:     "",
				Version:    "1.0",
				CreatedBy:  "test-system",
				Components: []types.Component{validComponent},
			},
			expectErrors: []string{"format is required"},
		},
		{
			name: "No components",
			sbom: &types.SBOM{
				Format:     types.SBOMFormatCycloneDX,
				Version:    "1.0",
				CreatedBy:  "test-system",
				Components: []types.Component{},
			},
			expectErrors: []string{"at least one component is required"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewValidator()
			validator.ValidateSBOM(tt.sbom)

			if len(tt.expectErrors) == 0 {
				assert.False(t, validator.HasErrors())
			} else {
				assert.True(t, validator.HasErrors())
				errors := validator.GetErrors()
				
				for _, expectedError := range tt.expectErrors {
					found := false
					for _, actualError := range errors {
						if actualError.Message == expectedError {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error message not found: %s", expectedError)
				}
			}
		})
	}
}

func TestIsValidName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid name", "test-artifact", true},
		{"Valid name with numbers", "test123", true},
		{"Valid name with dots", "test.artifact", true},
		{"Valid name with underscores", "test_artifact", true},
		{"Invalid name with special chars", "test@artifact", false},
		{"Invalid name starting with dash", "-test", false},
		{"Invalid name with spaces", "test artifact", false},
		{"Empty name", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Semantic version", "1.0.0", true},
		{"Version with patch", "1.0.0-alpha", true},
		{"Version with build", "1.0.0+build.1", true},
		{"Invalid version with double dots", "1..0", false},
		{"Invalid version with double slashes", "1//0", false},
		{"Invalid version with special chars", "1.0@0", false},
		{"Empty version", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidVersion(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidHash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid SHA256", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", true},
		{"Valid SHA1", "abcdef1234567890abcdef1234567890abcdef12", true},
		{"Invalid hash too short", "abc123", false},
		{"Invalid hash too long", string(make([]byte, 200)), false},
		{"Invalid hash with special chars", "abcdef@123", false},
		{"Empty hash", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidHash(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid HTTPS URL", "https://github.com/user/repo", true},
		{"Valid HTTP URL", "http://example.com", true},
		{"Valid Git URL", "git://github.com/user/repo.git", true},
		{"Valid SSH URL", "ssh://git@github.com/user/repo.git", true},
		{"Invalid URL without scheme", "github.com/user/repo", false},
		{"Invalid URL without host", "https://", false},
		{"Invalid scheme", "ftp://example.com", false},
		{"URL too long", "https://" + string(make([]byte, 2000)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func BenchmarkValidator_ValidateArtifact(b *testing.B) {
	artifact := &types.Artifact{
		ID:       uuid.New(),
		Name:     "benchmark-artifact",
		Version:  "1.0.0",
		Type:     types.ArtifactTypeContainer,
		Hash:     "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Size:     1024,
		Metadata: map[string]string{"env": "test", "region": "us-east-1"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		validator := NewValidator()
		validator.ValidateArtifact(artifact)
	}
}

func TestValidator_ValidationErrorDetails(t *testing.T) {
	validator := NewValidator()
	
	artifact := &types.Artifact{
		ID:      uuid.New(),
		Name:    "",
		Version: "",
		Type:    "",
	}
	
	validator.ValidateArtifact(artifact)
	
	assert.True(t, validator.HasErrors())
	errors := validator.GetErrors()
	
	assert.Len(t, errors, 3)
	
	errorMap := make(map[string]ValidationError)
	for _, err := range errors {
		errorMap[err.Field] = err
	}
	
	assert.Equal(t, "name is required", errorMap["name"].Message)
	assert.Equal(t, "REQUIRED", errorMap["name"].Code)
	
	assert.Equal(t, "version is required", errorMap["version"].Message)
	assert.Equal(t, "REQUIRED", errorMap["version"].Code)
	
	assert.Equal(t, "type is required", errorMap["type"].Message)
	assert.Equal(t, "REQUIRED", errorMap["type"].Code)
	
	assert.Contains(t, validator.Error(), "name: name is required")
	assert.Contains(t, validator.Error(), "version: version is required")
	assert.Contains(t, validator.Error(), "type: type is required")
}