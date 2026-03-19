package validation

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ValidationLevel defines the strictness of validation
type ValidationLevel string

const (
	ValidationLevelBasic        ValidationLevel = "basic"
	ValidationLevelStrict       ValidationLevel = "strict"
	ValidationLevelEnterprise   ValidationLevel = "enterprise"
)

// ValidationResult contains the result of a validation operation
type ValidationResult struct {
	Valid      bool                  `json:"valid"`
	Errors     []ValidationError     `json:"errors,omitempty"`
	Warnings   []ValidationWarning   `json:"warnings,omitempty"`
	Level      ValidationLevel       `json:"level"`
	Timestamp  time.Time            `json:"timestamp"`
	Context    map[string]interface{} `json:"context,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field      string `json:"field"`
	Message    string `json:"message"`
	Code       string `json:"code"`
	Suggestion string `json:"suggestion,omitempty"`
}

// AdvancedValidator provides comprehensive validation capabilities
type AdvancedValidator struct {
	level   ValidationLevel
	logger  *logrus.Logger
	rules   map[string]ValidationRule
}

// ValidationRule defines a validation rule
type ValidationRule interface {
	Name() string
	Validate(ctx context.Context, value interface{}) []ValidationError
}

// NewAdvancedValidator creates a new advanced validator
func NewAdvancedValidator(level ValidationLevel, logger *logrus.Logger) *AdvancedValidator {
	if logger == nil {
		logger = logrus.New()
	}

	validator := &AdvancedValidator{
		level:  level,
		logger: logger,
		rules:  make(map[string]ValidationRule),
	}

	// Register built-in rules
	validator.registerBuiltInRules()
	
	return validator
}

// ValidateArtifact validates an artifact with comprehensive checks
func (av *AdvancedValidator) ValidateArtifact(ctx context.Context, artifact *types.Artifact) ValidationResult {
	start := time.Now()
	result := ValidationResult{
		Valid:     true,
		Level:     av.level,
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
	}

	// Basic required field validation
	if artifact == nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    "artifact",
			Message:  "Artifact cannot be nil",
			Code:     "ARTIFACT_NULL",
			Severity: "error",
		})
		return result
	}

	// Validate UUID
	if artifact.ID == uuid.Nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:      "artifact.id",
			Message:    "Artifact ID is required",
			Code:       "MISSING_ARTIFACT_ID",
			Severity:   "error",
			Suggestion: "Generate a valid UUID for the artifact",
		})
	}

	// Validate name
	if strings.TrimSpace(artifact.Name) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:      "artifact.name",
			Message:    "Artifact name is required",
			Code:       "MISSING_ARTIFACT_NAME",
			Severity:   "error",
			Suggestion: "Provide a meaningful name for the artifact",
		})
	} else if err := av.validateArtifactName(artifact.Name); err != nil {
		result.Errors = append(result.Errors, *err)
		result.Valid = false
	}

	// Validate version
	if strings.TrimSpace(artifact.Version) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:      "artifact.version",
			Message:    "Artifact version is required",
			Code:       "MISSING_ARTIFACT_VERSION",
			Severity:   "error",
			Suggestion: "Use semantic versioning (e.g., 1.0.0)",
		})
	} else if err := av.validateVersion(artifact.Version); err != nil {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:      "artifact.version",
			Message:    err.Error(),
			Code:       "INVALID_VERSION_FORMAT",
			Suggestion: "Use semantic versioning format (major.minor.patch)",
		})
	}

	// Validate artifact type
	if err := av.validateArtifactType(artifact.Type); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}

	// Validate hash if provided
	if artifact.Hash != "" {
		if err := av.validateHash(artifact.Hash); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, *err)
		}
	} else if av.level == ValidationLevelStrict || av.level == ValidationLevelEnterprise {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:      "artifact.hash",
			Message:    "Artifact hash is required for strict validation",
			Code:       "MISSING_ARTIFACT_HASH",
			Severity:   "error",
			Suggestion: "Calculate and include SHA-256 hash of the artifact",
		})
	}

	// Validate timestamps
	if artifact.CreatedAt.IsZero() {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:      "artifact.created_at",
			Message:    "Creation timestamp not set",
			Code:       "MISSING_CREATED_AT",
			Suggestion: "Set creation timestamp for auditability",
		})
	} else if artifact.CreatedAt.After(time.Now()) {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    "artifact.created_at",
			Message:  "Creation timestamp cannot be in the future",
			Code:     "FUTURE_TIMESTAMP",
			Severity: "error",
		})
	}

	// Validate source if present
	if artifact.Source != nil {
		if sourceErrors := av.validateSource(artifact.Source); len(sourceErrors) > 0 {
			result.Errors = append(result.Errors, sourceErrors...)
			result.Valid = false
		}
	}

	// Validate SBOM if present
	if artifact.SBOM != nil {
		if sbomErrors := av.validateSBOM(artifact.SBOM); len(sbomErrors) > 0 {
			result.Errors = append(result.Errors, sbomErrors...)
			result.Valid = false
		}
	}

	// Validate signatures
	if len(artifact.Signatures) == 0 && av.level == ValidationLevelEnterprise {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:      "artifact.signatures",
			Message:    "At least one signature is required for enterprise validation",
			Code:       "MISSING_SIGNATURES",
			Severity:   "error",
			Suggestion: "Sign the artifact with a trusted key",
		})
	} else {
		for i, sig := range artifact.Signatures {
			if sigErrors := av.validateSignature(&sig, fmt.Sprintf("artifact.signatures[%d]", i)); len(sigErrors) > 0 {
				result.Errors = append(result.Errors, sigErrors...)
				result.Valid = false
			}
		}
	}

	// Add context information
	result.Context["validation_duration"] = time.Since(start).String()
	result.Context["total_errors"] = len(result.Errors)
	result.Context["total_warnings"] = len(result.Warnings)

	av.logger.WithFields(logrus.Fields{
		"artifact_id":     artifact.ID.String(),
		"artifact_name":   artifact.Name,
		"validation_time": time.Since(start),
		"valid":          result.Valid,
		"errors":         len(result.Errors),
		"warnings":       len(result.Warnings),
	}).Info("Artifact validation completed")

	return result
}

// ValidateBuildEvent validates a build event
func (av *AdvancedValidator) ValidateBuildEvent(ctx context.Context, event *types.BuildEvent) ValidationResult {
	result := ValidationResult{
		Valid:     true,
		Level:     av.level,
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
	}

	if event == nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    "build_event",
			Message:  "Build event cannot be nil",
			Code:     "BUILD_EVENT_NULL",
			Severity: "error",
		})
		return result
	}

	// Validate required fields
	if event.ID == uuid.Nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    "build_event.id",
			Message:  "Build event ID is required",
			Code:     "MISSING_BUILD_EVENT_ID",
			Severity: "error",
		})
	}

	if strings.TrimSpace(event.SourceRef) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:      "build_event.source_ref",
			Message:    "Source reference is required",
			Code:       "MISSING_SOURCE_REF",
			Severity:   "error",
			Suggestion: "Provide Git repository URL or local path",
		})
	}

	if strings.TrimSpace(event.CommitHash) == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:      "build_event.commit_hash",
			Message:    "Commit hash is required",
			Code:       "MISSING_COMMIT_HASH",
			Severity:   "error",
			Suggestion: "Provide Git commit SHA",
		})
	} else if !av.isValidCommitHash(event.CommitHash) {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:      "build_event.commit_hash",
			Message:    "Invalid commit hash format",
			Code:       "INVALID_COMMIT_HASH",
			Severity:   "error",
			Suggestion: "Use 40-character hexadecimal Git SHA",
		})
	}

	// Validate artifacts
	if len(event.Artifacts) == 0 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:      "build_event.artifacts",
			Message:    "No artifacts specified in build event",
			Code:       "NO_ARTIFACTS",
			Suggestion: "Include at least one artifact produced by the build",
		})
	} else {
		for i, artifact := range event.Artifacts {
			artifactResult := av.ValidateArtifact(ctx, &artifact)
			if !artifactResult.Valid {
				for _, err := range artifactResult.Errors {
					err.Field = fmt.Sprintf("build_event.artifacts[%d].%s", i, err.Field)
					result.Errors = append(result.Errors, err)
				}
				result.Valid = false
			}
		}
	}

	return result
}

// Helper validation methods
func (av *AdvancedValidator) validateArtifactName(name string) *ValidationError {
	// Allow alphanumeric, hyphens, underscores, and dots
	validNamePattern := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validNamePattern.MatchString(name) {
		return &ValidationError{
			Field:      "artifact.name",
			Message:    "Artifact name contains invalid characters",
			Code:       "INVALID_ARTIFACT_NAME",
			Severity:   "error",
			Suggestion: "Use only alphanumeric characters, hyphens, underscores, and dots",
		}
	}
	
	if len(name) > 255 {
		return &ValidationError{
			Field:      "artifact.name",
			Message:    "Artifact name is too long",
			Code:       "ARTIFACT_NAME_TOO_LONG",
			Severity:   "error",
			Suggestion: "Keep artifact name under 255 characters",
		}
	}
	
	return nil
}

func (av *AdvancedValidator) validateVersion(version string) error {
	// Basic semantic version check (major.minor.patch)
	semverPattern := regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$`)
	if !semverPattern.MatchString(version) {
		return fmt.Errorf("version does not follow semantic versioning format")
	}
	return nil
}

func (av *AdvancedValidator) validateArtifactType(artifactType types.ArtifactType) *ValidationError {
	validTypes := map[types.ArtifactType]bool{
		types.ArtifactTypeContainer: true,
		types.ArtifactTypeBinary:    true,
		types.ArtifactTypeMLModel:   true,
		types.ArtifactTypeLibrary:   true,
		types.ArtifactTypeDocument:  true,
	}
	
	if !validTypes[artifactType] {
		return &ValidationError{
			Field:      "artifact.type",
			Message:    fmt.Sprintf("Invalid artifact type: %s", artifactType),
			Code:       "INVALID_ARTIFACT_TYPE",
			Severity:   "error",
			Suggestion: "Use one of: container, binary, ml-model, library, document",
		}
	}
	
	return nil
}

func (av *AdvancedValidator) validateHash(hash string) *ValidationError {
	// Support common hash formats (SHA-256, SHA-512, etc.)
	hashPatterns := map[string]*regexp.Regexp{
		"SHA-256": regexp.MustCompile(`^[a-fA-F0-9]{64}$`),
		"SHA-512": regexp.MustCompile(`^[a-fA-F0-9]{128}$`),
		"SHA-1":   regexp.MustCompile(`^[a-fA-F0-9]{40}$`),
		"MD5":     regexp.MustCompile(`^[a-fA-F0-9]{32}$`),
	}
	
	for hashType, pattern := range hashPatterns {
		if pattern.MatchString(hash) {
			// MD5 and SHA-1 should trigger warnings in strict mode
			if (hashType == "MD5" || hashType == "SHA-1") && av.level == ValidationLevelEnterprise {
				return &ValidationError{
					Field:      "artifact.hash",
					Message:    fmt.Sprintf("%s is cryptographically weak", hashType),
					Code:       "WEAK_HASH_ALGORITHM",
					Severity:   "warning",
					Suggestion: "Use SHA-256 or stronger hash algorithm",
				}
			}
			return nil
		}
	}
	
	return &ValidationError{
		Field:      "artifact.hash",
		Message:    "Invalid hash format",
		Code:       "INVALID_HASH_FORMAT",
		Severity:   "error",
		Suggestion: "Use SHA-256 hash (64 hexadecimal characters)",
	}
}

func (av *AdvancedValidator) validateSource(source *types.Source) []ValidationError {
	var errors []ValidationError
	
	if source.ID == uuid.Nil {
		errors = append(errors, ValidationError{
			Field:    "source.id",
			Message:  "Source ID is required",
			Code:     "MISSING_SOURCE_ID",
			Severity: "error",
		})
	}
	
	if strings.TrimSpace(source.URL) == "" {
		errors = append(errors, ValidationError{
			Field:    "source.url",
			Message:  "Source URL is required",
			Code:     "MISSING_SOURCE_URL",
			Severity: "error",
		})
	} else {
		if _, err := url.Parse(source.URL); err != nil {
			errors = append(errors, ValidationError{
				Field:      "source.url",
				Message:    "Invalid source URL format",
				Code:       "INVALID_SOURCE_URL",
				Severity:   "error",
				Suggestion: "Provide a valid URL (e.g., https://github.com/user/repo.git)",
			})
		}
	}
	
	return errors
}

func (av *AdvancedValidator) validateSBOM(sbom *types.SBOM) []ValidationError {
	var errors []ValidationError
	
	if sbom.ID == uuid.Nil {
		errors = append(errors, ValidationError{
			Field:    "sbom.id",
			Message:  "SBOM ID is required",
			Code:     "MISSING_SBOM_ID",
			Severity: "error",
		})
	}
	
	validFormats := map[types.SBOMFormat]bool{
		types.SBOMFormatCycloneDX: true,
		types.SBOMFormatSPDX:      true,
		types.SBOMFormatSyft:      true,
	}
	
	if !validFormats[sbom.Format] {
		errors = append(errors, ValidationError{
			Field:      "sbom.format",
			Message:    fmt.Sprintf("Invalid SBOM format: %s", sbom.Format),
			Code:       "INVALID_SBOM_FORMAT",
			Severity:   "error",
			Suggestion: "Use CycloneDX, SPDX, or Syft format",
		})
	}
	
	return errors
}

func (av *AdvancedValidator) validateSignature(signature *types.Signature, fieldPrefix string) []ValidationError {
	var errors []ValidationError
	
	if signature.ID == uuid.Nil {
		errors = append(errors, ValidationError{
			Field:    fieldPrefix + ".id",
			Message:  "Signature ID is required",
			Code:     "MISSING_SIGNATURE_ID",
			Severity: "error",
		})
	}
	
	if strings.TrimSpace(signature.Value) == "" {
		errors = append(errors, ValidationError{
			Field:    fieldPrefix + ".value",
			Message:  "Signature value is required",
			Code:     "MISSING_SIGNATURE_VALUE",
			Severity: "error",
		})
	}
	
	return errors
}

func (av *AdvancedValidator) isValidCommitHash(hash string) bool {
	// Git commit hash is 40 character hexadecimal
	pattern := regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	return pattern.MatchString(hash)
}

// registerBuiltInRules registers built-in validation rules
func (av *AdvancedValidator) registerBuiltInRules() {
	// Add built-in rules based on validation level
	switch av.level {
	case ValidationLevelEnterprise:
		// Enterprise-specific rules
		av.rules["signature_required"] = &SignatureRequiredRule{}
		av.rules["provenance_required"] = &ProvenanceRequiredRule{}
		fallthrough
	case ValidationLevelStrict:
		// Strict validation rules
		av.rules["hash_required"] = &HashRequiredRule{}
		av.rules["secure_hash_only"] = &SecureHashOnlyRule{}
		fallthrough
	case ValidationLevelBasic:
		// Basic validation rules
		av.rules["required_fields"] = &RequiredFieldsRule{}
		av.rules["format_validation"] = &FormatValidationRule{}
	}
}

// Built-in validation rules
type RequiredFieldsRule struct{}
func (r *RequiredFieldsRule) Name() string { return "required_fields" }
func (r *RequiredFieldsRule) Validate(ctx context.Context, value interface{}) []ValidationError {
	// Implementation for required fields validation
	return []ValidationError{}
}

type FormatValidationRule struct{}
func (r *FormatValidationRule) Name() string { return "format_validation" }
func (r *FormatValidationRule) Validate(ctx context.Context, value interface{}) []ValidationError {
	// Implementation for format validation
	return []ValidationError{}
}

type HashRequiredRule struct{}
func (r *HashRequiredRule) Name() string { return "hash_required" }
func (r *HashRequiredRule) Validate(ctx context.Context, value interface{}) []ValidationError {
	// Implementation for hash requirement validation
	return []ValidationError{}
}

type SecureHashOnlyRule struct{}
func (r *SecureHashOnlyRule) Name() string { return "secure_hash_only" }
func (r *SecureHashOnlyRule) Validate(ctx context.Context, value interface{}) []ValidationError {
	// Implementation for secure hash validation
	return []ValidationError{}
}

type SignatureRequiredRule struct{}
func (r *SignatureRequiredRule) Name() string { return "signature_required" }
func (r *SignatureRequiredRule) Validate(ctx context.Context, value interface{}) []ValidationError {
	// Implementation for signature requirement validation
	return []ValidationError{}
}

type ProvenanceRequiredRule struct{}
func (r *ProvenanceRequiredRule) Name() string { return "provenance_required" }
func (r *ProvenanceRequiredRule) Validate(ctx context.Context, value interface{}) []ValidationError {
	// Implementation for provenance requirement validation
	return []ValidationError{}
}