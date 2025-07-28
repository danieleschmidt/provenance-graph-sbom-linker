# Test Fixtures

This directory contains test data, sample files, and other fixtures used across the test suites.

## Overview

Test fixtures provide consistent, reusable test data for unit, integration, and end-to-end tests. They help ensure tests are reproducible and maintainable.

## Structure

```
fixtures/
├── README.md                    # This file
├── artifacts/                   # Sample artifacts and SBOMs
│   ├── container-images/       # Container image test data
│   ├── binaries/               # Binary artifact test data
│   ├── sboms/                  # Sample SBOM files
│   └── signatures/             # Cryptographic signatures
├── repositories/               # Sample Git repositories
│   ├── go-app/                 # Sample Go application
│   ├── python-app/             # Sample Python application
│   └── multi-lang/             # Multi-language project
├── policies/                   # Security and compliance policies
│   ├── verification/           # Signature verification policies
│   ├── compliance/             # Compliance framework templates
│   └── security/               # Security scanning policies
├── certificates/               # Test certificates and keys
│   ├── ca/                     # Certificate Authority files
│   ├── cosign/                 # Cosign signing keys
│   └── tls/                    # TLS certificates
├── webhooks/                   # Sample webhook payloads
│   ├── github/                 # GitHub webhook examples
│   ├── gitlab/                 # GitLab webhook examples
│   └── generic/                # Generic CI/CD webhooks
├── databases/                  # Database test data
│   ├── neo4j/                  # Neo4j graph data
│   └── migrations/             # Test database migrations
└── api/                        # API test data
    ├── requests/               # Sample API requests
    ├── responses/              # Expected API responses
    └── schemas/                # API schema definitions
```

## Artifact Fixtures

### Container Images

Sample container image metadata and manifests:

```json
// fixtures/artifacts/container-images/sample-app-manifest.json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "size": 1234,
    "digest": "sha256:abc123def456"
  },
  "layers": [
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 5678,
      "digest": "sha256:fedcba654321"
    }
  ]
}
```

### SBOM Samples

#### CycloneDX SBOM
```json
// fixtures/artifacts/sboms/sample-cyclonedx.json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789012",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z",
    "tools": [
      {
        "vendor": "Provenance Linker",
        "name": "sbom-generator",
        "version": "1.0.0"
      }
    ],
    "component": {
      "type": "application",
      "bom-ref": "sample-app@1.0.0",
      "name": "sample-app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "github.com/gin-gonic/gin@1.9.1",
      "name": "gin",
      "version": "1.9.1",
      "purl": "pkg:golang/github.com/gin-gonic/gin@1.9.1",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    }
  ]
}
```

#### SPDX SBOM
```json
// fixtures/artifacts/sboms/sample-spdx.json
{
  "SPDXID": "SPDXRef-DOCUMENT",
  "spdxVersion": "SPDX-2.3",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Tool: provenance-linker-1.0.0"]
  },
  "name": "sample-app-1.0.0",
  "dataLicense": "CC0-1.0",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-sample-app",
      "name": "sample-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "copyrightText": "NOASSERTION"
    }
  ]
}
```

## Repository Fixtures

### Go Application
```
fixtures/repositories/go-app/
├── .git/                       # Git repository data
├── cmd/
│   └── main.go                # Application entry point
├── internal/
│   ├── handlers/              # HTTP handlers
│   └── services/              # Business logic
├── go.mod                     # Go module definition
├── go.sum                     # Go module checksums
├── Dockerfile                 # Container build
├── .provenance.yaml           # Provenance configuration
└── README.md                  # Project documentation
```

### Python Application
```
fixtures/repositories/python-app/
├── .git/                      # Git repository data
├── src/
│   ├── __init__.py
│   └── main.py               # Application entry point
├── requirements.txt          # Python dependencies
├── Dockerfile               # Container build
├── .provenance.yaml         # Provenance configuration
└── README.md                # Project documentation
```

## Policy Fixtures

### Verification Policy
```yaml
# fixtures/policies/verification/default-policy.yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: default-verification-policy
spec:
  images:
  - glob: "**"
    authorities:
    - key:
        data: |
          -----BEGIN PUBLIC KEY-----
          MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
          -----END PUBLIC KEY-----
  policy:
    fetchConfigFile: false
    type: "cue"
    data: |
      import "time"
      
      // Require signature timestamp within last 30 days
      predicateType: "https://slsa.dev/provenance/v0.2"
      predicate: buildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1"
```

### Compliance Policy
```yaml
# fixtures/policies/compliance/nist-ssdf.yaml
framework:
  name: "NIST SSDF"
  version: "1.1"
  
requirements:
  - id: "PO.1.1"
    description: "Identify and document all software components"
    checks:
      - type: "sbom_present"
        required: true
      - type: "component_inventory"
        threshold: 95
        
  - id: "PO.3.1"
    description: "Archive relevant artifacts"
    checks:
      - type: "artifact_retention"
        days: 365
      - type: "provenance_complete"
        required: true
        
  - id: "PS.1.1"
    description: "Protect source code integrity"
    checks:
      - type: "signed_commits"
        required: true
      - type: "branch_protection"
        required: true
```

## Certificate and Key Fixtures

### Cosign Test Keys
```bash
# Generate test keys for fixtures
cosign generate-key-pair --output-key-prefix fixtures/certificates/cosign/test
```

### TLS Certificates
```bash
# Generate self-signed certificates for testing
openssl req -x509 -newkey rsa:4096 -nodes -keyout fixtures/certificates/tls/localhost.key \
  -out fixtures/certificates/tls/localhost.crt -days 365 \
  -subj "/CN=localhost"
```

## Webhook Fixtures

### GitHub Push Event
```json
// fixtures/webhooks/github/push-event.json
{
  "ref": "refs/heads/main",
  "before": "0000000000000000000000000000000000000000",
  "after": "abc123def456789",
  "repository": {
    "id": 123456789,
    "name": "sample-repo",
    "full_name": "testorg/sample-repo",
    "private": false,
    "html_url": "https://github.com/testorg/sample-repo"
  },
  "pusher": {
    "name": "testuser",
    "email": "test@example.com"
  },
  "head_commit": {
    "id": "abc123def456789",
    "message": "Test commit for fixtures",
    "timestamp": "2024-01-01T00:00:00Z",
    "author": {
      "name": "Test User",
      "email": "test@example.com"
    },
    "added": ["src/new-file.go"],
    "removed": [],
    "modified": ["README.md"]
  }
}
```

### GitLab Push Event
```json
// fixtures/webhooks/gitlab/push-event.json
{
  "object_kind": "push",
  "before": "0000000000000000000000000000000000000000",
  "after": "abc123def456789",
  "ref": "refs/heads/main",
  "project": {
    "id": 123,
    "name": "sample-repo",
    "path_with_namespace": "testorg/sample-repo",
    "web_url": "https://gitlab.com/testorg/sample-repo"
  },
  "commits": [
    {
      "id": "abc123def456789",
      "message": "Test commit for fixtures",
      "timestamp": "2024-01-01T00:00:00Z",
      "author": {
        "name": "Test User",
        "email": "test@example.com"
      },
      "added": ["src/new-file.go"],
      "modified": ["README.md"],
      "removed": []
    }
  ]
}
```

## Database Fixtures

### Neo4j Test Data
```cypher
// fixtures/databases/neo4j/sample-data.cypher

// Create sample commit
CREATE (c:Commit {
  hash: 'abc123def456789',
  message: 'Test commit for fixtures',
  author: 'test@example.com',
  timestamp: datetime('2024-01-01T00:00:00Z')
})

// Create sample build
CREATE (b:Build {
  id: 'build-123',
  system: 'github-actions',
  workflow: '.github/workflows/build.yml',
  status: 'success',
  timestamp: datetime('2024-01-01T00:05:00Z')
})

// Create sample artifact
CREATE (a:Artifact {
  name: 'sample-app',
  version: '1.0.0',
  type: 'container',
  hash: 'sha256:fedcba654321',
  registry: 'ghcr.io/testorg',
  timestamp: datetime('2024-01-01T00:10:00Z')
})

// Create relationships
MATCH (c:Commit {hash: 'abc123def456789'})
MATCH (b:Build {id: 'build-123'})
MATCH (a:Artifact {name: 'sample-app'})
CREATE (c)-[:BUILT_INTO]->(b)
CREATE (b)-[:PRODUCES]->(a)
```

## API Fixtures

### Sample API Requests
```json
// fixtures/api/requests/track-build.json
{
  "source_ref": "git@github.com:testorg/sample-repo.git@main",
  "commit_hash": "abc123def456789",
  "build_system": "github-actions",
  "workflow": ".github/workflows/build.yml",
  "artifacts": [
    {
      "name": "sample-app",
      "version": "1.0.0",
      "type": "container",
      "hash": "sha256:fedcba654321",
      "registry": "ghcr.io/testorg",
      "sbom": {
        "format": "cyclonedx",
        "version": "1.4",
        "url": "https://example.com/sbom.json"
      }
    }
  ]
}
```

### Expected API Responses
```json
// fixtures/api/responses/provenance-graph.json
{
  "artifact": {
    "name": "sample-app",
    "version": "1.0.0",
    "type": "container"
  },
  "provenance": {
    "source": {
      "repository": "git@github.com:testorg/sample-repo.git",
      "commit": "abc123def456789",
      "branch": "main"
    },
    "build": {
      "system": "github-actions",
      "workflow": ".github/workflows/build.yml",
      "timestamp": "2024-01-01T00:05:00Z"
    },
    "sbom": {
      "format": "cyclonedx",
      "components_count": 42,
      "vulnerabilities_count": 0
    },
    "signature": {
      "algorithm": "ecdsa-p256-sha256",
      "keyid": "test-key-123",
      "verified": true
    }
  },
  "compliance": {
    "nist_ssdf": {
      "score": 85,
      "requirements_met": 12,
      "requirements_total": 14
    }
  }
}
```

## Usage in Tests

### Loading Fixtures

```go
// Test helper for loading fixtures
func LoadFixture(t *testing.T, path string) []byte {
    t.Helper()
    
    fullPath := filepath.Join("fixtures", path)
    data, err := os.ReadFile(fullPath)
    require.NoError(t, err, "Failed to load fixture: %s", path)
    
    return data
}

// Usage in tests
func TestSBOMParsing(t *testing.T) {
    sbomData := LoadFixture(t, "artifacts/sboms/sample-cyclonedx.json")
    
    var sbom types.SBOM
    err := json.Unmarshal(sbomData, &sbom)
    assert.NoError(t, err)
    assert.Equal(t, "CycloneDX", sbom.Format)
}
```

### Fixture Factories

```go
// Factory functions for creating test objects
func NewTestBuildEvent() *types.BuildEvent {
    return &types.BuildEvent{
        SourceRef:  "git@github.com:testorg/sample-repo.git@main",
        CommitHash: "abc123def456789",
        BuildSystem: "github-actions",
        Artifacts: []types.Artifact{
            NewTestArtifact(),
        },
    }
}

func NewTestArtifact() types.Artifact {
    return types.Artifact{
        Name:    "sample-app",
        Version: "1.0.0",
        Type:    "container",
        Hash:    "sha256:fedcba654321",
    }
}
```

## Maintenance

### Updating Fixtures

1. **Version Control**: All fixtures are version controlled
2. **Documentation**: Document changes to fixture data
3. **Backward Compatibility**: Maintain compatibility with existing tests
4. **Cleanup**: Remove unused fixtures regularly

### Validation

```bash
# Validate JSON fixtures
find fixtures -name "*.json" -exec jsonlint {} \;

# Validate YAML fixtures
find fixtures -name "*.yaml" -exec yamllint {} \;

# Validate SBOM fixtures
find fixtures/artifacts/sboms -name "*.json" -exec sbom-validator {} \;
```

## Security Considerations

1. **No Real Secrets**: Never include real certificates, keys, or secrets
2. **Test-Only Data**: Clearly mark all data as test-only
3. **Sanitized Data**: Remove any potentially sensitive information
4. **Key Rotation**: Regularly regenerate test keys and certificates

## Best Practices

1. **Realistic Data**: Use realistic but fake data
2. **Comprehensive Coverage**: Cover common and edge cases
3. **Organized Structure**: Keep fixtures well-organized and documented
4. **Reusable Components**: Create reusable fixture components
5. **Regular Updates**: Keep fixtures current with schema changes

This fixture directory provides comprehensive test data to support thorough testing across all test suites while maintaining security and maintainability.