package types

import (
	"time"

	"github.com/google/uuid"
)

type Artifact struct {
	ID           uuid.UUID          `json:"id" neo4j:"id"`
	Name         string             `json:"name" neo4j:"name"`
	Version      string             `json:"version" neo4j:"version"`
	Type         ArtifactType       `json:"type" neo4j:"type"`
	Hash         string             `json:"hash" neo4j:"hash"`
	Size         int64              `json:"size" neo4j:"size"`
	CreatedAt    time.Time          `json:"created_at" neo4j:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at" neo4j:"updated_at"`
	Source       *Source            `json:"source,omitempty" neo4j:"source"`
	SBOM         *SBOM              `json:"sbom,omitempty" neo4j:"sbom"`
	Signatures   []Signature        `json:"signatures" neo4j:"signatures"`
	Metadata     map[string]string  `json:"metadata" neo4j:"metadata"`
	Dependencies []Dependency       `json:"dependencies" neo4j:"dependencies"`
	Attestations []Attestation      `json:"attestations" neo4j:"attestations"`
}

type ArtifactType string

const (
	ArtifactTypeContainer ArtifactType = "container"
	ArtifactTypeBinary    ArtifactType = "binary"
	ArtifactTypeMLModel   ArtifactType = "ml-model"
	ArtifactTypeLibrary   ArtifactType = "library"
	ArtifactTypeDocument  ArtifactType = "document"
)

type Source struct {
	ID         uuid.UUID         `json:"id" neo4j:"id"`
	Type       SourceType        `json:"type" neo4j:"type"`
	URL        string            `json:"url" neo4j:"url"`
	Branch     string            `json:"branch" neo4j:"branch"`
	CommitHash string            `json:"commit_hash" neo4j:"commit_hash"`
	Tag        string            `json:"tag,omitempty" neo4j:"tag"`
	Metadata   map[string]string `json:"metadata" neo4j:"metadata"`
	CreatedAt  time.Time         `json:"created_at" neo4j:"created_at"`
}

type SourceType string

const (
	SourceTypeGit    SourceType = "git"
	SourceTypeSVN    SourceType = "svn"
	SourceTypeLocal  SourceType = "local"
	SourceTypeRemote SourceType = "remote"
)

type SBOM struct {
	ID          uuid.UUID         `json:"id" neo4j:"id"`
	Format      SBOMFormat        `json:"format" neo4j:"format"`
	Version     string            `json:"version" neo4j:"version"`
	CreatedAt   time.Time         `json:"created_at" neo4j:"created_at"`
	CreatedBy   string            `json:"created_by" neo4j:"created_by"`
	Components  []Component       `json:"components" neo4j:"components"`
	Metadata    map[string]string `json:"metadata" neo4j:"metadata"`
	Hash        string            `json:"hash" neo4j:"hash"`
	Serialized  []byte            `json:"serialized,omitempty" neo4j:"-"`
}

type SBOMFormat string

const (
	SBOMFormatCycloneDX SBOMFormat = "cyclonedx"
	SBOMFormatSPDX      SBOMFormat = "spdx"
	SBOMFormatSyft      SBOMFormat = "syft"
)

type Component struct {
	ID           uuid.UUID         `json:"id" neo4j:"id"`
	Name         string            `json:"name" neo4j:"name"`
	Version      string            `json:"version" neo4j:"version"`
	Type         ComponentType     `json:"type" neo4j:"type"`
	Namespace    string            `json:"namespace,omitempty" neo4j:"namespace"`
	License      []string          `json:"license" neo4j:"license"`
	Hash         string            `json:"hash,omitempty" neo4j:"hash"`
	Supplier     string            `json:"supplier,omitempty" neo4j:"supplier"`
	Homepage     string            `json:"homepage,omitempty" neo4j:"homepage"`
	Description  string            `json:"description,omitempty" neo4j:"description"`
	Metadata     map[string]string `json:"metadata" neo4j:"metadata"`
}

type ComponentType string

const (
	ComponentTypeLibrary      ComponentType = "library"
	ComponentTypeApplication  ComponentType = "application"
	ComponentTypeFramework    ComponentType = "framework"
	ComponentTypeOS           ComponentType = "operating-system"
	ComponentTypeDevice       ComponentType = "device"
	ComponentTypeFirmware     ComponentType = "firmware"
	ComponentTypeContainer    ComponentType = "container"
	ComponentTypeFile         ComponentType = "file"
)

type Dependency struct {
	ID        uuid.UUID      `json:"id" neo4j:"id"`
	From      uuid.UUID      `json:"from" neo4j:"from"`
	To        uuid.UUID      `json:"to" neo4j:"to"`
	Type      DependencyType `json:"type" neo4j:"type"`
	Scope     string         `json:"scope,omitempty" neo4j:"scope"`
	Optional  bool           `json:"optional" neo4j:"optional"`
	CreatedAt time.Time      `json:"created_at" neo4j:"created_at"`
}

type DependencyType string

const (
	DependencyTypeDirect    DependencyType = "direct"
	DependencyTypeTransitive DependencyType = "transitive"
	DependencyTypeDev        DependencyType = "dev"
	DependencyTypeTest       DependencyType = "test"
	DependencyTypeRuntime    DependencyType = "runtime"
)

type Signature struct {
	ID          uuid.UUID       `json:"id" neo4j:"id"`
	Algorithm   SignatureType   `json:"algorithm" neo4j:"algorithm"`
	Value       string          `json:"value" neo4j:"value"`
	KeyID       string          `json:"key_id" neo4j:"key_id"`
	Certificate string          `json:"certificate,omitempty" neo4j:"certificate"`
	Timestamp   time.Time       `json:"timestamp" neo4j:"timestamp"`
	Metadata    map[string]string `json:"metadata" neo4j:"metadata"`
}

type SignatureType string

const (
	SignatureTypeCosign SignatureType = "cosign"
	SignatureTypeGPG    SignatureType = "gpg"
	SignatureTypeX509   SignatureType = "x509"
	SignatureTypeJWT    SignatureType = "jwt"
)

type Attestation struct {
	ID          uuid.UUID         `json:"id" neo4j:"id"`
	Type        AttestationType   `json:"type" neo4j:"type"`
	Predicate   map[string]interface{} `json:"predicate" neo4j:"predicate"`
	Subject     []Subject         `json:"subject" neo4j:"subject"`
	Signature   *Signature        `json:"signature,omitempty" neo4j:"signature"`
	CreatedAt   time.Time         `json:"created_at" neo4j:"created_at"`
	Metadata    map[string]string `json:"metadata" neo4j:"metadata"`
}

type AttestationType string

const (
	AttestationTypeSLSA      AttestationType = "https://slsa.dev/provenance/v1"
	AttestationTypeLinkage   AttestationType = "https://in-toto.io/Statement/v1"
	AttestationTypeTest      AttestationType = "https://witness.testifysec.com/attestation-collection/v1"
	AttestationTypeVuln      AttestationType = "https://in-toto.io/attestation/vuln/v1"
	AttestationTypeLicense   AttestationType = "https://in-toto.io/attestation/license/v1"
	AttestationTypeSBOM      AttestationType = "https://in-toto.io/attestation/sbom/v1"
)

type Subject struct {
	Name   string            `json:"name" neo4j:"name"`
	Digest map[string]string `json:"digest" neo4j:"digest"`
}

type BuildEvent struct {
	ID           uuid.UUID         `json:"id"`
	SourceRef    string            `json:"source_ref"`
	CommitHash   string            `json:"commit_hash"`
	BuildID      string            `json:"build_id,omitempty"`
	BuildSystem  string            `json:"build_system,omitempty"`
	BuildURL     string            `json:"build_url,omitempty"`
	Artifacts    []Artifact        `json:"artifacts"`
	Timestamp    time.Time         `json:"timestamp"`
	Metadata     map[string]string `json:"metadata"`
}

type DeploymentEvent struct {
	ID           uuid.UUID         `json:"id"`
	ArtifactID   uuid.UUID         `json:"artifact_id"`
	Environment  string            `json:"environment"`
	Target       string            `json:"target"`
	DeploymentID string            `json:"deployment_id"`
	Status       DeploymentStatus  `json:"status"`
	Timestamp    time.Time         `json:"timestamp"`
	Metadata     map[string]string `json:"metadata"`
}

type DeploymentStatus string

const (
	DeploymentStatusPending   DeploymentStatus = "pending"
	DeploymentStatusRunning   DeploymentStatus = "running"
	DeploymentStatusSucceeded DeploymentStatus = "succeeded"
	DeploymentStatusFailed    DeploymentStatus = "failed"
)

type ProvenanceGraph struct {
	ID        uuid.UUID  `json:"id"`
	Nodes     []Node     `json:"nodes"`
	Edges     []Edge     `json:"edges"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time  `json:"created_at"`
}

type Node struct {
	ID       string      `json:"id"`
	Type     NodeType    `json:"type"`
	Label    string      `json:"label"`
	Data     interface{} `json:"data"`
	Metadata map[string]string `json:"metadata"`
}

type NodeType string

const (
	NodeTypeSource     NodeType = "source"
	NodeTypeBuild      NodeType = "build"
	NodeTypeArtifact   NodeType = "artifact"
	NodeTypeDeployment NodeType = "deployment"
	NodeTypeComponent  NodeType = "component"
)

type Edge struct {
	ID       string            `json:"id"`
	From     string            `json:"from"`
	To       string            `json:"to"`
	Type     EdgeType          `json:"type"`
	Label    string            `json:"label"`
	Metadata map[string]string `json:"metadata"`
}

type EdgeType string

const (
	EdgeTypeBuiltFrom   EdgeType = "built_from"
	EdgeTypeDeployedTo  EdgeType = "deployed_to"
	EdgeTypeDependsOn   EdgeType = "depends_on"
	EdgeTypeContains    EdgeType = "contains"
	EdgeTypeAttests     EdgeType = "attests"
	EdgeTypeSigns       EdgeType = "signs"
)

type ComplianceReport struct {
	ID          uuid.UUID              `json:"id"`
	Standard    ComplianceStandard     `json:"standard"`
	ProjectName string                 `json:"project_name"`
	Version     string                 `json:"version"`
	Status      ComplianceStatus       `json:"status"`
	Score       float64                `json:"score"`
	Requirements []RequirementResult   `json:"requirements"`
	Evidence    []Evidence             `json:"evidence"`
	GeneratedAt time.Time              `json:"generated_at"`
	GeneratedBy string                 `json:"generated_by"`
	Metadata    map[string]string      `json:"metadata"`
}

type ComplianceStandard string

const (
	ComplianceStandardNISTSSDF ComplianceStandard = "nist-ssdf"
	ComplianceStandardEUCRA    ComplianceStandard = "eu-cra"
	ComplianceStandardCustom   ComplianceStandard = "custom"
)

type ComplianceStatus string

const (
	ComplianceStatusCompliant    ComplianceStatus = "compliant"
	ComplianceStatusNonCompliant ComplianceStatus = "non-compliant"
	ComplianceStatusPartial      ComplianceStatus = "partial"
	ComplianceStatusUnknown      ComplianceStatus = "unknown"
)

type RequirementResult struct {
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Status      ComplianceStatus    `json:"status"`
	Evidence    []string            `json:"evidence"`
	Details     string              `json:"details,omitempty"`
	Score       float64             `json:"score"`
}

type Evidence struct {
	ID          uuid.UUID         `json:"id"`
	Type        EvidenceType      `json:"type"`
	Source      string            `json:"source"`
	Description string            `json:"description"`
	Data        interface{}       `json:"data"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
}

type EvidenceType string

const (
	EvidenceTypeSignature     EvidenceType = "signature"
	EvidenceTypeAttestation   EvidenceType = "attestation"
	EvidenceTypeSBOM          EvidenceType = "sbom"
	EvidenceTypeVulnerability EvidenceType = "vulnerability"
	EvidenceTypeBuild         EvidenceType = "build"
	EvidenceTypeTest          EvidenceType = "test"
)