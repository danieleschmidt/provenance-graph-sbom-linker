package testutil

import (
	"fmt"
	"time"
)

// TestArtifact represents a test artifact
type TestArtifact struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      string            `json:"type"`
	Hash      string            `json:"hash"`
	Registry  string            `json:"registry,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// TestBuildEvent represents a test build event
type TestBuildEvent struct {
	ID           string         `json:"id"`
	SourceRef    string         `json:"source_ref"`
	CommitHash   string         `json:"commit_hash"`
	BuildSystem  string         `json:"build_system"`
	Workflow     string         `json:"workflow,omitempty"`
	Branch       string         `json:"branch"`
	Artifacts    []TestArtifact `json:"artifacts"`
	Status       string         `json:"status"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	Environment  string         `json:"environment"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// TestSBOM represents a test SBOM
type TestSBOM struct {
	Format           string                 `json:"format"`
	Version          string                 `json:"version"`
	SerialNumber     string                 `json:"serial_number"`
	Components       []TestSBOMComponent    `json:"components"`
	Dependencies     []TestSBOMDependency   `json:"dependencies,omitempty"`
	Vulnerabilities  []TestVulnerability    `json:"vulnerabilities,omitempty"`
	Metadata         map[string]any         `json:"metadata,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
}

// TestSBOMComponent represents a component in a test SBOM
type TestSBOMComponent struct {
	Type      string            `json:"type"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	PURL      string            `json:"purl,omitempty"`
	CPE       string            `json:"cpe,omitempty"`
	Licenses  []string          `json:"licenses,omitempty"`
	Hash      string            `json:"hash,omitempty"`
	Scope     string            `json:"scope,omitempty"`
	Supplier  string            `json:"supplier,omitempty"`
	Publisher string            `json:"publisher,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

// TestSBOMDependency represents a dependency relationship in a test SBOM
type TestSBOMDependency struct {
	Ref          string   `json:"ref"`
	DependsOn    []string `json:"depends_on"`
	Relationship string   `json:"relationship,omitempty"`
}

// TestVulnerability represents a test vulnerability
type TestVulnerability struct {
	ID          string                  `json:"id"`
	Source      string                  `json:"source"`
	Severity    string                  `json:"severity"`
	Score       float64                 `json:"score,omitempty"`
	Vector      string                  `json:"vector,omitempty"`
	Description string                  `json:"description"`
	References  []string                `json:"references,omitempty"`
	Affects     []TestVulnerableComponent `json:"affects"`
	PublishedAt time.Time               `json:"published_at"`
	UpdatedAt   *time.Time              `json:"updated_at,omitempty"`
}

// TestVulnerableComponent represents a component affected by a vulnerability
type TestVulnerableComponent struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	VersionRange   string   `json:"version_range,omitempty"`
	FixedIn        []string `json:"fixed_in,omitempty"`
}

// TestSignature represents a test signature
type TestSignature struct {
	Algorithm   string            `json:"algorithm"`
	KeyID       string            `json:"key_id"`
	Signature   string            `json:"signature"`
	PublicKey   string            `json:"public_key,omitempty"`
	Certificate string            `json:"certificate,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	ValidUntil  *time.Time        `json:"valid_until,omitempty"`
}

// TestAttestation represents a test attestation
type TestAttestation struct {
	Type         string         `json:"type"`
	PredicateType string        `json:"predicate_type"`
	Subject      []TestSubject  `json:"subject"`
	Predicate    map[string]any `json:"predicate"`
	Signature    TestSignature  `json:"signature"`
	CreatedAt    time.Time      `json:"created_at"`
}

// TestSubject represents a subject in a test attestation
type TestSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Factory functions for creating test objects

// NewTestArtifact creates a new test artifact with default values
func NewTestArtifact() TestArtifact {
	now := time.Now()
	return TestArtifact{
		Name:      "test-app",
		Version:   "1.0.0",
		Type:      "container",
		Hash:      "sha256:abc123def456",
		Registry:  "registry.example.com",
		Tags:      []string{"latest"},
		Labels: map[string]string{
			"maintainer": "test@example.com",
			"version":    "1.0.0",
		},
		CreatedAt: now,
	}
}

// NewTestArtifactWithName creates a new test artifact with specified name
func NewTestArtifactWithName(name string) TestArtifact {
	artifact := NewTestArtifact()
	artifact.Name = name
	return artifact
}

// NewTestBuildEvent creates a new test build event with default values
func NewTestBuildEvent() TestBuildEvent {
	now := time.Now()
	completedAt := now.Add(5 * time.Minute)
	
	return TestBuildEvent{
		ID:          "build-12345",
		SourceRef:   "git@github.com:testorg/test-repo.git@main",
		CommitHash:  "abc123def456789",
		BuildSystem: "github-actions",
		Workflow:    ".github/workflows/build.yml",
		Branch:      "main",
		Artifacts:   []TestArtifact{NewTestArtifact()},
		Status:      "success",
		StartedAt:   now,
		CompletedAt: &completedAt,
		Environment: "ci",
		Metadata: map[string]any{
			"run_id":     "123456789",
			"run_number": "42",
			"actor":      "testuser",
		},
	}
}

// NewTestSBOM creates a new test SBOM with default values
func NewTestSBOM() TestSBOM {
	now := time.Now()
	
	return TestSBOM{
		Format:       "CycloneDX",
		Version:      "1.4",
		SerialNumber: "urn:uuid:12345678-1234-1234-1234-123456789012",
		Components: []TestSBOMComponent{
			{
				Type:    "application",
				Name:    "test-app",
				Version: "1.0.0",
				PURL:    "pkg:generic/test-app@1.0.0",
				Licenses: []string{"MIT"},
				Hash:    "sha256:abc123def456",
				Scope:   "required",
			},
			{
				Type:    "library",
				Name:    "example-lib",
				Version: "2.1.0",
				PURL:    "pkg:npm/example-lib@2.1.0",
				Licenses: []string{"Apache-2.0"},
				Hash:    "sha256:def456abc123",
				Scope:   "required",
			},
		},
		Dependencies: []TestSBOMDependency{
			{
				Ref:       "test-app@1.0.0",
				DependsOn: []string{"example-lib@2.1.0"},
			},
		},
		Vulnerabilities: []TestVulnerability{
			NewTestVulnerability(),
		},
		CreatedAt: now,
		Metadata: map[string]any{
			"tool":    "test-sbom-generator",
			"version": "1.0.0",
		},
	}
}

// NewTestVulnerability creates a new test vulnerability with default values
func NewTestVulnerability() TestVulnerability {
	now := time.Now()
	
	return TestVulnerability{
		ID:          "CVE-2024-12345",
		Source:      "NVD",
		Severity:    "HIGH",
		Score:       7.5,
		Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		Description: "Test vulnerability for demonstration purposes",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
			"https://example.com/advisory/12345",
		},
		Affects: []TestVulnerableComponent{
			{
				Name:         "example-lib",
				Version:      "2.1.0",
				VersionRange: ">=2.0.0,<2.2.0",
				FixedIn:      []string{"2.2.0"},
			},
		},
		PublishedAt: now.Add(-24 * time.Hour),
	}
}

// NewTestSignature creates a new test signature with default values
func NewTestSignature() TestSignature {
	now := time.Now()
	validUntil := now.Add(365 * 24 * time.Hour) // Valid for 1 year
	
	return TestSignature{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     "test-key-12345",
		Signature: "MEUCIQD1234567890abcdef...",
		PublicKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
		Annotations: map[string]string{
			"build_id":    "build-12345",
			"commit_sha":  "abc123def456789",
			"build_time":  now.Format(time.RFC3339),
		},
		CreatedAt:  now,
		ValidUntil: &validUntil,
	}
}

// NewTestAttestation creates a new test attestation with default values
func NewTestAttestation() TestAttestation {
	now := time.Now()
	
	return TestAttestation{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://slsa.dev/provenance/v0.2",
		Subject: []TestSubject{
			{
				Name: "test-app:1.0.0",
				Digest: map[string]string{
					"sha256": "abc123def456",
				},
			},
		},
		Predicate: map[string]any{
			"builder": map[string]any{
				"id": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			},
			"buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			"invocation": map[string]any{
				"configSource": map[string]any{
					"uri":        "git+https://github.com/testorg/test-repo@refs/heads/main",
					"digest":     map[string]string{"sha1": "abc123def456789"},
					"entryPoint": ".github/workflows/build.yml",
				},
			},
			"metadata": map[string]any{
				"buildInvocationId": "build-12345",
				"completeness": map[string]any{
					"parameters":  true,
					"environment": false,
					"materials":   true,
				},
				"reproducible": false,
			},
			"materials": []map[string]any{
				{
					"uri": "git+https://github.com/testorg/test-repo@refs/heads/main",
					"digest": map[string]string{
						"sha1": "abc123def456789",
					},
				},
			},
		},
		Signature: NewTestSignature(),
		CreatedAt: now,
	}
}

// Builder pattern methods for customizing test objects

// ArtifactBuilder provides a fluent interface for building test artifacts
type ArtifactBuilder struct {
	artifact TestArtifact
}

// NewArtifactBuilder creates a new artifact builder
func NewArtifactBuilder() *ArtifactBuilder {
	return &ArtifactBuilder{
		artifact: NewTestArtifact(),
	}
}

// WithName sets the artifact name
func (b *ArtifactBuilder) WithName(name string) *ArtifactBuilder {
	b.artifact.Name = name
	return b
}

// WithVersion sets the artifact version
func (b *ArtifactBuilder) WithVersion(version string) *ArtifactBuilder {
	b.artifact.Version = version
	return b
}

// WithType sets the artifact type
func (b *ArtifactBuilder) WithType(artifactType string) *ArtifactBuilder {
	b.artifact.Type = artifactType
	return b
}

// WithHash sets the artifact hash
func (b *ArtifactBuilder) WithHash(hash string) *ArtifactBuilder {
	b.artifact.Hash = hash
	return b
}

// WithRegistry sets the artifact registry
func (b *ArtifactBuilder) WithRegistry(registry string) *ArtifactBuilder {
	b.artifact.Registry = registry
	return b
}

// WithTags sets the artifact tags
func (b *ArtifactBuilder) WithTags(tags ...string) *ArtifactBuilder {
	b.artifact.Tags = tags
	return b
}

// WithLabel adds a label to the artifact
func (b *ArtifactBuilder) WithLabel(key, value string) *ArtifactBuilder {
	if b.artifact.Labels == nil {
		b.artifact.Labels = make(map[string]string)
	}
	b.artifact.Labels[key] = value
	return b
}

// Build returns the built artifact
func (b *ArtifactBuilder) Build() TestArtifact {
	return b.artifact
}

// BuildEventBuilder provides a fluent interface for building test build events
type BuildEventBuilder struct {
	event TestBuildEvent
}

// NewBuildEventBuilder creates a new build event builder
func NewBuildEventBuilder() *BuildEventBuilder {
	return &BuildEventBuilder{
		event: NewTestBuildEvent(),
	}
}

// WithID sets the build ID
func (b *BuildEventBuilder) WithID(id string) *BuildEventBuilder {
	b.event.ID = id
	return b
}

// WithSourceRef sets the source reference
func (b *BuildEventBuilder) WithSourceRef(sourceRef string) *BuildEventBuilder {
	b.event.SourceRef = sourceRef
	return b
}

// WithCommitHash sets the commit hash
func (b *BuildEventBuilder) WithCommitHash(commitHash string) *BuildEventBuilder {
	b.event.CommitHash = commitHash
	return b
}

// WithBuildSystem sets the build system
func (b *BuildEventBuilder) WithBuildSystem(buildSystem string) *BuildEventBuilder {
	b.event.BuildSystem = buildSystem
	return b
}

// WithBranch sets the branch
func (b *BuildEventBuilder) WithBranch(branch string) *BuildEventBuilder {
	b.event.Branch = branch
	return b
}

// WithArtifacts sets the artifacts
func (b *BuildEventBuilder) WithArtifacts(artifacts ...TestArtifact) *BuildEventBuilder {
	b.event.Artifacts = artifacts
	return b
}

// WithStatus sets the build status
func (b *BuildEventBuilder) WithStatus(status string) *BuildEventBuilder {
	b.event.Status = status
	return b
}

// WithEnvironment sets the environment
func (b *BuildEventBuilder) WithEnvironment(environment string) *BuildEventBuilder {
	b.event.Environment = environment
	return b
}

// WithMetadata adds metadata to the build event
func (b *BuildEventBuilder) WithMetadata(key string, value any) *BuildEventBuilder {
	if b.event.Metadata == nil {
		b.event.Metadata = make(map[string]any)
	}
	b.event.Metadata[key] = value
	return b
}

// Build returns the built build event
func (b *BuildEventBuilder) Build() TestBuildEvent {
	return b.event
}

// Utility functions for generating test data

// GenerateTestHash generates a test hash with the specified algorithm
func GenerateTestHash(algorithm string) string {
	switch algorithm {
	case "sha256":
		return fmt.Sprintf("sha256:%s", RandomString(64))
	case "sha1":
		return fmt.Sprintf("sha1:%s", RandomString(40))
	case "md5":
		return fmt.Sprintf("md5:%s", RandomString(32))
	default:
		return fmt.Sprintf("sha256:%s", RandomString(64))
	}
}

// GenerateTestPURL generates a test Package URL
func GenerateTestPURL(packageType, name, version string) string {
	return fmt.Sprintf("pkg:%s/%s@%s", packageType, name, version)
}

// GenerateTestCPE generates a test Common Platform Enumeration
func GenerateTestCPE(vendor, product, version string) string {
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}