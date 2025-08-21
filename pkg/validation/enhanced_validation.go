package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

// ValidationRule represents a single validation rule
type ValidationRule struct {
	Name        string
	Field       string
	Rule        func(interface{}) error
	Required    bool
	ErrorMsg    string
}

// Using existing ValidationResult and ValidationError from security.go

// EnhancedValidator provides comprehensive validation capabilities
type EnhancedValidator struct {
	rules     map[string][]ValidationRule
	patterns  map[string]*regexp.Regexp
}

// NewEnhancedValidator creates a new enhanced validator
func NewEnhancedValidator() *EnhancedValidator {
	ev := &EnhancedValidator{
		rules:    make(map[string][]ValidationRule),
		patterns: make(map[string]*regexp.Regexp),
	}
	
	// Initialize common patterns
	ev.initializePatterns()
	
	// Setup default validation rules
	ev.setupDefaultRules()
	
	return ev
}

// initializePatterns sets up commonly used regex patterns
func (ev *EnhancedValidator) initializePatterns() {
	patterns := map[string]string{
		"email":    `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
		"url":      `^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$`,
		"uuid":     `^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
		"semver":   `^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`,
		"sha256":   `^[a-fA-F0-9]{64}$`,
		"path":     `^\/[a-zA-Z0-9\/_-]*$`,
		"filename": `^[a-zA-Z0-9._-]+$`,
	}
	
	for name, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			ev.patterns[name] = regex
		}
	}
}

// setupDefaultRules sets up default validation rules for common types
func (ev *EnhancedValidator) setupDefaultRules() {
	// Artifact validation rules
	ev.rules["artifact"] = []ValidationRule{
		{
			Name:     "name_required",
			Field:    "name",
			Required: true,
			Rule: func(v interface{}) error {
				name, ok := v.(string)
				if !ok || strings.TrimSpace(name) == "" {
					return fmt.Errorf("name is required")
				}
				if len(name) > 100 {
					return fmt.Errorf("name too long (max 100 characters)")
				}
				if !ev.isValidIdentifier(name) {
					return fmt.Errorf("name contains invalid characters")
				}
				return nil
			},
		},
		{
			Name:     "version_required",
			Field:    "version",
			Required: true,
			Rule: func(v interface{}) error {
				version, ok := v.(string)
				if !ok || strings.TrimSpace(version) == "" {
					return fmt.Errorf("version is required")
				}
				if len(version) > 50 {
					return fmt.Errorf("version too long (max 50 characters)")
				}
				// Allow semver or simple version patterns
				if !ev.isValidVersion(version) {
					return fmt.Errorf("invalid version format")
				}
				return nil
			},
		},
		{
			Name:     "type_valid",
			Field:    "type",
			Required: true,
			Rule: func(v interface{}) error {
				artifactType, ok := v.(string)
				if !ok {
					return fmt.Errorf("type must be a string")
				}
				validTypes := []string{"container", "binary", "ml-model", "library", "document"}
				for _, validType := range validTypes {
					if artifactType == validType {
						return nil
					}
				}
				return fmt.Errorf("invalid artifact type: %s", artifactType)
			},
		},
		{
			Name:  "hash_format",
			Field: "hash",
			Rule: func(v interface{}) error {
				hash, ok := v.(string)
				if !ok {
					return fmt.Errorf("hash must be a string")
				}
				if hash != "" && !ev.patterns["sha256"].MatchString(hash) {
					return fmt.Errorf("invalid hash format (expected SHA256)")
				}
				return nil
			},
		},
	}
	
	// SBOM validation rules
	ev.rules["sbom"] = []ValidationRule{
		{
			Name:     "format_valid",
			Field:    "format",
			Required: true,
			Rule: func(v interface{}) error {
				format, ok := v.(string)
				if !ok {
					return fmt.Errorf("format must be a string")
				}
				validFormats := []string{"cyclonedx", "spdx", "syft"}
				for _, validFormat := range validFormats {
					if format == validFormat {
						return nil
					}
				}
				return fmt.Errorf("invalid SBOM format: %s", format)
			},
		},
		{
			Name:     "version_required",
			Field:    "version",
			Required: true,
			Rule: func(v interface{}) error {
				version, ok := v.(string)
				if !ok || strings.TrimSpace(version) == "" {
					return fmt.Errorf("SBOM version is required")
				}
				return nil
			},
		},
	}
	
	// Component validation rules
	ev.rules["component"] = []ValidationRule{
		{
			Name:     "name_required",
			Field:    "name",
			Required: true,
			Rule: func(v interface{}) error {
				name, ok := v.(string)
				if !ok || strings.TrimSpace(name) == "" {
					return fmt.Errorf("component name is required")
				}
				if len(name) > 200 {
					return fmt.Errorf("component name too long (max 200 characters)")
				}
				return nil
			},
		},
		{
			Name:     "type_valid",
			Field:    "type",
			Required: true,
			Rule: func(v interface{}) error {
				componentType, ok := v.(string)
				if !ok {
					return fmt.Errorf("component type must be a string")
				}
				validTypes := []string{"library", "application", "framework", "operating-system", "device", "firmware", "container", "file"}
				for _, validType := range validTypes {
					if componentType == validType {
						return nil
					}
				}
				return fmt.Errorf("invalid component type: %s", componentType)
			},
		},
		{
			Name:  "licenses_valid",
			Field: "licenses",
			Rule: func(v interface{}) error {
				licenses, ok := v.([]string)
				if !ok {
					return fmt.Errorf("licenses must be a string array")
				}
				for _, license := range licenses {
					if !ev.isValidLicense(license) {
						return fmt.Errorf("invalid license identifier: %s", license)
					}
				}
				return nil
			},
		},
	}
}

// ValidateArtifact validates an artifact object
func (ev *EnhancedValidator) ValidateArtifact(artifact *types.Artifact) ValidationResult {
	if artifact == nil {
		return ValidationResult{
			Valid:  false,
			Errors: []ValidationError{{Field: "artifact", Message: "artifact cannot be nil", Code: "REQUIRED"}},
		}
	}
	
	result := ValidationResult{Valid: true, Errors: []ValidationError{}}
	
	// Validate using registered rules
	if rules, exists := ev.rules["artifact"]; exists {
		for _, rule := range rules {
			var fieldValue interface{}
			switch rule.Field {
			case "name":
				fieldValue = artifact.Name
			case "version":
				fieldValue = artifact.Version
			case "type":
				fieldValue = string(artifact.Type)
			case "hash":
				fieldValue = artifact.Hash
			}
			
			if err := rule.Rule(fieldValue); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Field:   rule.Field,
					Message: err.Error(),
					Code:    strings.ToUpper(rule.Name),
				})
			}
		}
	}
	
	// Additional validations
	if artifact.Size < 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "size",
			Message: "size cannot be negative",
			Code:    "INVALID_SIZE",
		})
	}
	
	// Validate metadata
	if err := ev.validateMetadata(artifact.Metadata); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "metadata",
			Message: err.Error(),
			Code:    "INVALID_METADATA",
		})
	}
	
	return result
}

// ValidateSBOM validates an SBOM object
func (ev *EnhancedValidator) ValidateSBOM(sbom *types.SBOM) ValidationResult {
	if sbom == nil {
		return ValidationResult{
			Valid:  false,
			Errors: []ValidationError{{Field: "sbom", Message: "SBOM cannot be nil", Code: "REQUIRED"}},
		}
	}
	
	result := ValidationResult{Valid: true, Errors: []ValidationError{}}
	
	// Validate using registered rules
	if rules, exists := ev.rules["sbom"]; exists {
		for _, rule := range rules {
			var fieldValue interface{}
			switch rule.Field {
			case "format":
				fieldValue = string(sbom.Format)
			case "version":
				fieldValue = sbom.Version
			}
			
			if err := rule.Rule(fieldValue); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Field:   rule.Field,
					Message: err.Error(),
					Code:    strings.ToUpper(rule.Name),
				})
			}
		}
	}
	
	// Validate components
	for i, component := range sbom.Components {
		componentResult := ev.ValidateComponent(&component)
		if !componentResult.Valid {
			for _, err := range componentResult.Errors {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Field:   fmt.Sprintf("components[%d].%s", i, err.Field),
					Message: err.Message,
					Code:    err.Code,
				})
			}
		}
	}
	
	return result
}

// ValidateComponent validates a component object
func (ev *EnhancedValidator) ValidateComponent(component *types.Component) ValidationResult {
	if component == nil {
		return ValidationResult{
			Valid:  false,
			Errors: []ValidationError{{Field: "component", Message: "component cannot be nil", Code: "REQUIRED"}},
		}
	}
	
	result := ValidationResult{Valid: true, Errors: []ValidationError{}}
	
	// Validate using registered rules
	if rules, exists := ev.rules["component"]; exists {
		for _, rule := range rules {
			var fieldValue interface{}
			switch rule.Field {
			case "name":
				fieldValue = component.Name
			case "type":
				fieldValue = string(component.Type)
			case "licenses":
				fieldValue = component.License
			}
			
			if err := rule.Rule(fieldValue); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Field:   rule.Field,
					Message: err.Error(),
					Code:    strings.ToUpper(rule.Name),
				})
			}
		}
	}
	
	return result
}

// ValidateInput performs general input sanitization and validation
func (ev *EnhancedValidator) ValidateInput(input string, rules ...string) error {
	if input == "" {
		return nil
	}
	
	// Check for null bytes and control characters
	if strings.Contains(input, "\x00") {
		return fmt.Errorf("input contains null bytes")
	}
	
	// Apply specific rules
	for _, rule := range rules {
		switch rule {
		case "no-sql-injection":
			if ev.containsSQLInjection(input) {
				return fmt.Errorf("input contains potential SQL injection")
			}
		case "no-xss":
			if ev.containsXSS(input) {
				return fmt.Errorf("input contains potential XSS")
			}
		case "no-path-traversal":
			if ev.containsPathTraversal(input) {
				return fmt.Errorf("input contains path traversal patterns")
			}
		case "url":
			if !ev.isValidURL(input) {
				return fmt.Errorf("invalid URL format")
			}
		case "email":
			if !ev.patterns["email"].MatchString(input) {
				return fmt.Errorf("invalid email format")
			}
		}
	}
	
	return nil
}

// Helper functions

func (ev *EnhancedValidator) isValidIdentifier(name string) bool {
	// Allow alphanumeric, hyphens, underscores, dots
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, name)
	return matched
}

func (ev *EnhancedValidator) isValidVersion(version string) bool {
	// Check for semver first
	if ev.patterns["semver"].MatchString(version) {
		return true
	}
	
	// Allow simple version patterns like 1.0, v1.2.3, 2021.01
	simpleVersion, _ := regexp.MatchString(`^v?[0-9]+(\.[0-9]+)*(-[a-zA-Z0-9.-]+)?$`, version)
	return simpleVersion
}

func (ev *EnhancedValidator) isValidLicense(license string) bool {
	// Common SPDX license identifiers
	commonLicenses := []string{
		"MIT", "Apache-2.0", "GPL-2.0", "GPL-3.0", "BSD-2-Clause", "BSD-3-Clause",
		"ISC", "MPL-2.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "Unlicense",
	}
	
	for _, validLicense := range commonLicenses {
		if license == validLicense {
			return true
		}
	}
	
	// Allow custom license formats
	if strings.HasPrefix(license, "LicenseRef-") {
		return true
	}
	
	return false
}

func (ev *EnhancedValidator) isValidURL(input string) bool {
	if ev.patterns["url"].MatchString(input) {
		return true
	}
	
	// Additional URL validation
	if _, err := url.Parse(input); err != nil {
		return false
	}
	
	return true
}

func (ev *EnhancedValidator) validateMetadata(metadata map[string]string) error {
	if metadata == nil {
		return nil
	}
	
	// Limit metadata size
	if len(metadata) > 50 {
		return fmt.Errorf("too many metadata entries (max 50)")
	}
	
	for key, value := range metadata {
		if len(key) > 100 {
			return fmt.Errorf("metadata key too long: %s", key)
		}
		if len(value) > 1000 {
			return fmt.Errorf("metadata value too long for key: %s", key)
		}
		
		// Sanitize key and value
		if err := ev.ValidateInput(key, "no-sql-injection", "no-xss"); err != nil {
			return fmt.Errorf("invalid metadata key %s: %v", key, err)
		}
		if err := ev.ValidateInput(value, "no-sql-injection", "no-xss"); err != nil {
			return fmt.Errorf("invalid metadata value for key %s: %v", key, err)
		}
	}
	
	return nil
}

func (ev *EnhancedValidator) containsSQLInjection(input string) bool {
	sqlPatterns := []string{
		`(?i)(union\s+select|select\s+\*\s+from|drop\s+table|delete\s+from)`,
		`(?i)(insert\s+into|update\s+set|alter\s+table)`,
		`(?i)(\'\s*or\s*\d+=\d+|1\s*=\s*1|\'\s*;\s*--)`,
	}
	
	for _, pattern := range sqlPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			return true
		}
	}
	
	return false
}

func (ev *EnhancedValidator) containsXSS(input string) bool {
	xssPatterns := []string{
		`(?i)(<script|</script>|javascript:|vbscript:)`,
		`(?i)(onload\s*=|onclick\s*=|onerror\s*=|onmouseover\s*=)`,
		`(?i)(eval\s*\(|expression\s*\(|url\s*\()`,
	}
	
	for _, pattern := range xssPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			return true
		}
	}
	
	return false
}

func (ev *EnhancedValidator) containsPathTraversal(input string) bool {
	pathTraversalPatterns := []string{
		`\.\.\/`,
		`\.\.\\`,
		`%2e%2e%2f`,
		`%2e%2e\\`,
		`%252e%252e%252f`,
	}
	
	inputLower := strings.ToLower(input)
	for _, pattern := range pathTraversalPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}
	
	return false
}

// GenerateSecureHashEnhanced generates a secure hash for the given input with timestamp
func GenerateSecureHashEnhanced(input string) string {
	hash := sha256.Sum256([]byte(input + time.Now().String()))
	return hex.EncodeToString(hash[:])
}