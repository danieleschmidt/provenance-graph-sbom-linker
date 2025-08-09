package validation

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

// SecurityValidator provides security validation functions
type SecurityValidator struct {
	allowedOrigins []string
	trustedDomains []string
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error in field '%s': %s", e.Field, e.Message)
}

type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
}

func NewSecurityValidator(allowedOrigins, trustedDomains []string) *SecurityValidator {
	return &SecurityValidator{
		allowedOrigins: allowedOrigins,
		trustedDomains: trustedDomains,
	}
}

func (v *SecurityValidator) ValidateArtifact(artifact *types.Artifact) ValidationResult {
	var errors []ValidationError

	// Validate basic fields
	if err := v.validateRequiredString(artifact.Name, "name"); err != nil {
		errors = append(errors, *err)
	}

	if err := v.validateRequiredString(artifact.Version, "version"); err != nil {
		errors = append(errors, *err)
	}

	// Validate hash format
	if artifact.Hash != "" {
		if err := v.validateHash(artifact.Hash); err != nil {
			errors = append(errors, ValidationError{
				Field:   "hash",
				Message: err.Error(),
				Code:    "INVALID_HASH",
			})
		}
	}

	// Validate metadata for injection attacks
	if err := v.validateMetadata(artifact.Metadata); err != nil {
		errors = append(errors, *err)
	}

	// Validate artifact type
	if !v.isValidArtifactType(string(artifact.Type)) {
		errors = append(errors, ValidationError{
			Field:   "type",
			Message: "Invalid artifact type",
			Code:    "INVALID_TYPE",
		})
	}

	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}

func (v *SecurityValidator) ValidateSource(source *types.Source) ValidationResult {
	var errors []ValidationError

	// Validate URL
	if err := v.validateURL(source.URL); err != nil {
		errors = append(errors, ValidationError{
			Field:   "url",
			Message: err.Error(),
			Code:    "INVALID_URL",
		})
	}

	// Validate commit hash
	if source.CommitHash != "" {
		if err := v.validateCommitHash(source.CommitHash); err != nil {
			errors = append(errors, ValidationError{
				Field:   "commit_hash",
				Message: err.Error(),
				Code:    "INVALID_COMMIT_HASH",
			})
		}
	}

	// Validate branch name
	if source.Branch != "" {
		if err := v.validateBranchName(source.Branch); err != nil {
			errors = append(errors, ValidationError{
				Field:   "branch",
				Message: err.Error(),
				Code:    "INVALID_BRANCH",
			})
		}
	}

	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}

func (v *SecurityValidator) ValidateSBOM(sbom *types.SBOM) ValidationResult {
	var errors []ValidationError

	// Validate format
	if !v.isValidSBOMFormat(string(sbom.Format)) {
		errors = append(errors, ValidationError{
			Field:   "format",
			Message: "Invalid SBOM format",
			Code:    "INVALID_FORMAT",
		})
	}

	// Validate created_by
	if sbom.CreatedBy == "" {
		errors = append(errors, ValidationError{
			Field:   "created_by",
			Message: "created_by is required",
			Code:    "REQUIRED_FIELD",
		})
	}

	// Validate components
	for i, component := range sbom.Components {
		if componentErrors := v.validateComponent(&component, fmt.Sprintf("components[%d]", i)); len(componentErrors) > 0 {
			errors = append(errors, componentErrors...)
		}
	}

	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}

func (v *SecurityValidator) validateComponent(component *types.Component, fieldPrefix string) []ValidationError {
	var errors []ValidationError

	// Validate name
	if err := v.validateRequiredString(component.Name, fieldPrefix+".name"); err != nil {
		errors = append(errors, *err)
	}

	// Validate version
	if err := v.validateRequiredString(component.Version, fieldPrefix+".version"); err != nil {
		errors = append(errors, *err)
	}

	// Validate licenses
	for i, license := range component.License {
		if err := v.validateLicense(license); err != nil {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("%s.license[%d]", fieldPrefix, i),
				Message: err.Error(),
				Code:    "INVALID_LICENSE",
			})
		}
	}

	return errors
}

func (v *SecurityValidator) validateRequiredString(value, field string) *ValidationError {
	if strings.TrimSpace(value) == "" {
		return &ValidationError{
			Field:   field,
			Message: "Field is required",
			Code:    "REQUIRED_FIELD",
		}
	}

	// Check for injection attacks
	if v.containsSQLInjection(value) || v.containsXSS(value) {
		return &ValidationError{
			Field:   field,
			Message: "Field contains potentially malicious content",
			Code:    "MALICIOUS_CONTENT",
		}
	}

	return nil
}

func (v *SecurityValidator) validateHash(hash string) error {
	// Check for common hash formats
	patterns := map[string]*regexp.Regexp{
		"sha256": regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`),
		"sha1":   regexp.MustCompile(`^sha1:[a-fA-F0-9]{40}$`),
		"md5":    regexp.MustCompile(`^md5:[a-fA-F0-9]{32}$`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(hash) {
			return nil
		}
	}

	return fmt.Errorf("invalid hash format")
}

func (v *SecurityValidator) validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL is required")
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
	}

	// Check allowed schemes
	allowedSchemes := []string{"https", "http", "git", "ssh"}
	if !contains(allowedSchemes, parsedURL.Scheme) {
		return fmt.Errorf("scheme '%s' not allowed", parsedURL.Scheme)
	}

	// Check for trusted domains if configured
	if len(v.trustedDomains) > 0 {
		if !v.isDomainTrusted(parsedURL.Host) {
			return fmt.Errorf("domain '%s' not in trusted domains", parsedURL.Host)
		}
	}

	return nil
}

func (v *SecurityValidator) validateCommitHash(hash string) error {
	// Git commit hashes are 40 character hex strings (SHA-1) or 64 character (SHA-256)
	if len(hash) != 40 && len(hash) != 64 {
		return fmt.Errorf("invalid commit hash length")
	}

	for _, char := range hash {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return fmt.Errorf("invalid commit hash format")
		}
	}

	return nil
}

func (v *SecurityValidator) validateBranchName(branch string) error {
	// Git branch name validation
	if strings.HasPrefix(branch, ".") || strings.HasSuffix(branch, ".") {
		return fmt.Errorf("branch name cannot start or end with a dot")
	}

	if strings.Contains(branch, "..") {
		return fmt.Errorf("branch name cannot contain consecutive dots")
	}

	// Check for dangerous characters
	dangerousChars := []string{" ", "~", "^", ":", "?", "*", "[", "\\"}
	for _, char := range dangerousChars {
		if strings.Contains(branch, char) {
			return fmt.Errorf("branch name contains invalid character: %s", char)
		}
	}

	return nil
}

func (v *SecurityValidator) validateLicense(license string) error {
	// Basic license validation
	if strings.TrimSpace(license) == "" {
		return fmt.Errorf("license cannot be empty")
	}

	// Check for common SPDX license identifiers
	spdxPattern := regexp.MustCompile(`^[A-Za-z0-9\.\-\+]+$`)
	if !spdxPattern.MatchString(license) {
		return fmt.Errorf("invalid license format")
	}

	return nil
}

func (v *SecurityValidator) validateMetadata(metadata map[string]string) *ValidationError {
	for key, value := range metadata {
		if v.containsSQLInjection(key) || v.containsSQLInjection(value) {
			return &ValidationError{
				Field:   "metadata",
				Message: "Metadata contains potentially malicious content",
				Code:    "MALICIOUS_CONTENT",
			}
		}

		if v.containsXSS(key) || v.containsXSS(value) {
			return &ValidationError{
				Field:   "metadata",
				Message: "Metadata contains potentially malicious scripts",
				Code:    "XSS_CONTENT",
			}
		}
	}

	return nil
}

func (v *SecurityValidator) containsSQLInjection(input string) bool {
	input = strings.ToLower(input)
	sqlPatterns := []string{
		"select", "insert", "update", "delete", "drop", "create", "alter",
		"union", "exec", "execute", "sp_", "xp_", "--|", "/*", "*/",
		"'", "\"", ";", "=", "<", ">",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}

	return false
}

func (v *SecurityValidator) containsXSS(input string) bool {
	input = strings.ToLower(input)
	xssPatterns := []string{
		"<script", "</script>", "javascript:", "onload=", "onerror=",
		"onclick=", "onmouseover=", "alert(", "document.cookie",
		"window.location", "eval(", "setTimeout(", "setInterval(",
	}

	for _, pattern := range xssPatterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}

	return false
}

func (v *SecurityValidator) isValidArtifactType(artifactType string) bool {
	validTypes := []string{
		string(types.ArtifactTypeContainer),
		string(types.ArtifactTypeBinary),
		string(types.ArtifactTypeMLModel),
		string(types.ArtifactTypeLibrary),
		string(types.ArtifactTypeDocument),
	}

	return contains(validTypes, artifactType)
}

func (v *SecurityValidator) isValidSBOMFormat(format string) bool {
	validFormats := []string{
		string(types.SBOMFormatCycloneDX),
		string(types.SBOMFormatSPDX),
		string(types.SBOMFormatSyft),
	}

	return contains(validFormats, format)
}

func (v *SecurityValidator) isDomainTrusted(domain string) bool {
	for _, trusted := range v.trustedDomains {
		if domain == trusted {
			return true
		}
		// Allow subdomains of trusted domains
		if strings.HasSuffix(domain, "."+trusted) {
			return true
		}
	}
	return false
}

// SanitizeInput sanitizes user input to prevent injection attacks
func (v *SecurityValidator) SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Remove control characters except tab, newline, and carriage return
	cleaned := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, input)

	// Trim whitespace
	return strings.TrimSpace(cleaned)
}

// GenerateSecureHash generates a secure hash of the input
func GenerateSecureHash(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return fmt.Sprintf("sha256:%x", hasher.Sum(nil))
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Additional validation methods for Generation 2
func (v *SecurityValidator) isValidArtifactName(name string) bool {
	// Artifact names should follow container naming conventions
	pattern := regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)
	return pattern.MatchString(name)
}

func (v *SecurityValidator) isValidVersion(version string) bool {
	// Support semantic versioning and other common formats
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`^\d+\.\d+\.\d+$`),                    // Semantic versioning
		regexp.MustCompile(`^\d+\.\d+\.\d+-[a-zA-Z0-9.-]+$`),   // Pre-release
		regexp.MustCompile(`^v\d+\.\d+\.\d+$`),                 // v-prefixed
		regexp.MustCompile(`^(latest|main|master)$`),              // Special versions
		regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,127}$`),  // General format
	}
	
	for _, pattern := range patterns {
		if pattern.MatchString(version) {
			return true
		}
	}
	return false
}

func (v *SecurityValidator) isValidHash(hash string) bool {
	// Support various hash formats
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`),
		regexp.MustCompile(`^sha1:[a-fA-F0-9]{40}$`),
		regexp.MustCompile(`^md5:[a-fA-F0-9]{32}$`),
		regexp.MustCompile(`^[a-fA-F0-9]{32}$`),   // MD5
		regexp.MustCompile(`^[a-fA-F0-9]{40}$`),   // SHA1
		regexp.MustCompile(`^[a-fA-F0-9]{64}$`),   // SHA256
	}
	
	for _, pattern := range patterns {
		if pattern.MatchString(hash) {
			return true
		}
	}
	return false
}