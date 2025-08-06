package validation

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

type Validator struct {
	errors []ValidationError
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func NewValidator() *Validator {
	return &Validator{
		errors: make([]ValidationError, 0),
	}
}

func (v *Validator) AddError(field, message, code string) {
	v.errors = append(v.errors, ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	})
}

func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

func (v *Validator) GetErrors() []ValidationError {
	return v.errors
}

func (v *Validator) Error() string {
	if len(v.errors) == 0 {
		return ""
	}

	var messages []string
	for _, err := range v.errors {
		messages = append(messages, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}
	return strings.Join(messages, "; ")
}

func (v *Validator) ValidateArtifact(artifact *types.Artifact) {
	if artifact == nil {
		v.AddError("artifact", "artifact cannot be nil", "REQUIRED")
		return
	}

	if artifact.Name == "" {
		v.AddError("name", "name is required", "REQUIRED")
	} else if len(artifact.Name) > 255 {
		v.AddError("name", "name cannot exceed 255 characters", "MAX_LENGTH")
	} else if !isValidName(artifact.Name) {
		v.AddError("name", "name contains invalid characters", "INVALID_FORMAT")
	}

	if artifact.Version == "" {
		v.AddError("version", "version is required", "REQUIRED")
	} else if len(artifact.Version) > 100 {
		v.AddError("version", "version cannot exceed 100 characters", "MAX_LENGTH")
	} else if !isValidVersion(artifact.Version) {
		v.AddError("version", "version format is invalid", "INVALID_FORMAT")
	}

	if artifact.Type == "" {
		v.AddError("type", "type is required", "REQUIRED")
	} else if !isValidArtifactType(artifact.Type) {
		v.AddError("type", "invalid artifact type", "INVALID_VALUE")
	}

	if artifact.Hash != "" && !isValidHash(artifact.Hash) {
		v.AddError("hash", "hash format is invalid", "INVALID_FORMAT")
	}

	if artifact.Size < 0 {
		v.AddError("size", "size cannot be negative", "INVALID_VALUE")
	}

	if artifact.Size > 10*1024*1024*1024 { // 10GB max
		v.AddError("size", "size cannot exceed 10GB", "MAX_VALUE")
	}

	v.validateMetadata(artifact.Metadata, "metadata")
}

func (v *Validator) ValidateSource(source *types.Source) {
	if source == nil {
		v.AddError("source", "source cannot be nil", "REQUIRED")
		return
	}

	if source.URL == "" {
		v.AddError("url", "url is required", "REQUIRED")
	} else if !isValidURL(source.URL) {
		v.AddError("url", "url format is invalid", "INVALID_FORMAT")
	}

	if source.Type == "" {
		v.AddError("type", "type is required", "REQUIRED")
	} else if !isValidSourceType(source.Type) {
		v.AddError("type", "invalid source type", "INVALID_VALUE")
	}

	if source.CommitHash != "" && !isValidCommitHash(source.CommitHash) {
		v.AddError("commit_hash", "commit hash format is invalid", "INVALID_FORMAT")
	}

	if source.Branch != "" && len(source.Branch) > 255 {
		v.AddError("branch", "branch name cannot exceed 255 characters", "MAX_LENGTH")
	}

	v.validateMetadata(source.Metadata, "metadata")
}

func (v *Validator) ValidateSBOM(sbom *types.SBOM) {
	if sbom == nil {
		v.AddError("sbom", "sbom cannot be nil", "REQUIRED")
		return
	}

	if sbom.Format == "" {
		v.AddError("format", "format is required", "REQUIRED")
	} else if !isValidSBOMFormat(sbom.Format) {
		v.AddError("format", "invalid SBOM format", "INVALID_VALUE")
	}

	if sbom.Version == "" {
		v.AddError("version", "version is required", "REQUIRED")
	}

	if sbom.CreatedBy == "" {
		v.AddError("created_by", "created_by is required", "REQUIRED")
	}

	if len(sbom.Components) == 0 {
		v.AddError("components", "at least one component is required", "REQUIRED")
	}

	for i, component := range sbom.Components {
		v.ValidateComponent(&component, fmt.Sprintf("components[%d]", i))
	}

	v.validateMetadata(sbom.Metadata, "metadata")
}

func (v *Validator) ValidateComponent(component *types.Component, fieldPrefix string) {
	if component == nil {
		v.AddError(fieldPrefix, "component cannot be nil", "REQUIRED")
		return
	}

	if component.Name == "" {
		v.AddError(fieldPrefix+".name", "name is required", "REQUIRED")
	} else if len(component.Name) > 255 {
		v.AddError(fieldPrefix+".name", "name cannot exceed 255 characters", "MAX_LENGTH")
	}

	if component.Version == "" {
		v.AddError(fieldPrefix+".version", "version is required", "REQUIRED")
	} else if !isValidVersion(component.Version) {
		v.AddError(fieldPrefix+".version", "version format is invalid", "INVALID_FORMAT")
	}

	if component.Type == "" {
		v.AddError(fieldPrefix+".type", "type is required", "REQUIRED")
	} else if !isValidComponentType(component.Type) {
		v.AddError(fieldPrefix+".type", "invalid component type", "INVALID_VALUE")
	}

	for i, license := range component.License {
		if license == "" {
			v.AddError(fmt.Sprintf("%s.license[%d]", fieldPrefix, i), "license cannot be empty", "REQUIRED")
		} else if len(license) > 100 {
			v.AddError(fmt.Sprintf("%s.license[%d]", fieldPrefix, i), "license cannot exceed 100 characters", "MAX_LENGTH")
		}
	}

	if component.Homepage != "" && !isValidURL(component.Homepage) {
		v.AddError(fieldPrefix+".homepage", "homepage URL format is invalid", "INVALID_FORMAT")
	}

	v.validateMetadata(component.Metadata, fieldPrefix+".metadata")
}

func (v *Validator) validateMetadata(metadata map[string]string, fieldPrefix string) {
	if len(metadata) > 50 {
		v.AddError(fieldPrefix, "metadata cannot have more than 50 entries", "MAX_ITEMS")
	}

	for key, value := range metadata {
		if key == "" {
			v.AddError(fieldPrefix, "metadata key cannot be empty", "REQUIRED")
		} else if len(key) > 100 {
			v.AddError(fieldPrefix, "metadata key cannot exceed 100 characters", "MAX_LENGTH")
		}

		if len(value) > 1000 {
			v.AddError(fieldPrefix, "metadata value cannot exceed 1000 characters", "MAX_LENGTH")
		}

		if !isValidMetadataKey(key) {
			v.AddError(fieldPrefix, "metadata key contains invalid characters", "INVALID_FORMAT")
		}
	}
}

func isValidName(name string) bool {
	nameRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	return nameRegex.MatchString(name)
}

func isValidVersion(version string) bool {
	if strings.Contains(version, "..") || strings.Contains(version, "//") {
		return false
	}
	
	versionRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]*$`)
	return versionRegex.MatchString(version)
}

func isValidHash(hash string) bool {
	if len(hash) < 32 || len(hash) > 128 {
		return false
	}
	
	hashRegex := regexp.MustCompile(`^[a-fA-F0-9]+$`)
	return hashRegex.MatchString(hash)
}

func isValidURL(urlStr string) bool {
	if len(urlStr) > 2000 {
		return false
	}
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return false
	}

	allowedSchemes := map[string]bool{
		"http":  true,
		"https": true,
		"git":   true,
		"ssh":   true,
		"file":  true,
	}

	return allowedSchemes[parsedURL.Scheme]
}

func isValidCommitHash(hash string) bool {
	if len(hash) != 40 {
		return false
	}
	
	hashRegex := regexp.MustCompile(`^[a-fA-F0-9]+$`)
	return hashRegex.MatchString(hash)
}

func isValidMetadataKey(key string) bool {
	if len(key) == 0 {
		return false
	}

	for _, r := range key {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.' {
			return false
		}
	}

	return true
}

func isValidArtifactType(artifactType types.ArtifactType) bool {
	validTypes := map[types.ArtifactType]bool{
		types.ArtifactTypeContainer: true,
		types.ArtifactTypeBinary:    true,
		types.ArtifactTypeMLModel:   true,
		types.ArtifactTypeLibrary:   true,
		types.ArtifactTypeDocument:  true,
	}
	return validTypes[artifactType]
}

func isValidSourceType(sourceType types.SourceType) bool {
	validTypes := map[types.SourceType]bool{
		types.SourceTypeGit:    true,
		types.SourceTypeSVN:    true,
		types.SourceTypeLocal:  true,
		types.SourceTypeRemote: true,
	}
	return validTypes[sourceType]
}

func isValidSBOMFormat(format types.SBOMFormat) bool {
	validFormats := map[types.SBOMFormat]bool{
		types.SBOMFormatCycloneDX: true,
		types.SBOMFormatSPDX:      true,
		types.SBOMFormatSyft:      true,
	}
	return validFormats[format]
}

func isValidComponentType(componentType types.ComponentType) bool {
	validTypes := map[types.ComponentType]bool{
		types.ComponentTypeLibrary:      true,
		types.ComponentTypeApplication:  true,
		types.ComponentTypeFramework:    true,
		types.ComponentTypeOS:           true,
		types.ComponentTypeDevice:       true,
		types.ComponentTypeFirmware:     true,
		types.ComponentTypeContainer:    true,
		types.ComponentTypeFile:         true,
	}
	return validTypes[componentType]
}