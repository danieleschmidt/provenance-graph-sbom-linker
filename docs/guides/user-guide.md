# User Guide

This comprehensive guide covers all aspects of using the Provenance Graph SBOM Linker for tracking your software supply chain.

## Table of Contents

- [Getting Started](#getting-started)
- [Basic Usage](#basic-usage)
- [Advanced Features](#advanced-features)
- [Integration Patterns](#integration-patterns)
- [Compliance Workflows](#compliance-workflows)
- [Troubleshooting](#troubleshooting)

## Getting Started

### Prerequisites

- Docker (for containerized deployment)
- Kubernetes cluster (for production deployment)
- Git repository access
- Container registry access

### Installation Methods

#### CLI Installation
```bash
# Download latest release
curl -L https://github.com/your-org/provenance-graph-sbom-linker/releases/latest/download/provenance-linker_$(uname -s)_$(uname -m).tar.gz | tar xz
sudo mv provenance-linker /usr/local/bin/

# Verify installation
provenance-linker version
```

#### Docker Usage
```bash
# Pull the image
docker pull your-org/provenance-linker:latest

# Run with mounted workspace
docker run -v $(pwd):/workspace your-org/provenance-linker:latest --help
```

### Initial Configuration

1. **Initialize Configuration**
   ```bash
   provenance-linker init --config-dir ~/.provenance
   ```

2. **Configure Database Connection**
   ```yaml
   # ~/.provenance/config.yaml
   database:
     type: neo4j
     uri: bolt://localhost:7687
     username: neo4j
     password: your-password
   
   server:
     port: 8080
     host: localhost
   ```

3. **Verify Setup**
   ```bash
   provenance-linker health-check
   ```

## Basic Usage

### Tracking Your First Artifact

1. **Initialize Project Tracking**
   ```bash
   provenance-linker init --project my-application
   ```

2. **Track a Build**
   ```bash
   provenance-linker track build \
     --source-ref=git@github.com:org/repo.git@main \
     --commit=abc123def \
     --artifact=my-app:v1.0.0 \
     --sbom=sbom.cyclonedx.json \
     --build-system=github-actions
   ```

3. **Sign the Artifact**
   ```bash
   provenance-linker sign \
     --artifact=my-app:v1.0.0 \
     --key-file=cosign.key \
     --annotations="build-id=12345,commit=abc123def"
   ```

4. **Verify and Deploy**
   ```bash
   provenance-linker verify \
     --artifact=my-app:v1.0.0 \
     --policy=verification-policy.yaml
   
   provenance-linker track deployment \
     --artifact=my-app:v1.0.0 \
     --environment=production \
     --platform=kubernetes
   ```

### Generating Reports

#### Provenance Graph
```bash
# Generate complete provenance graph
provenance-linker graph \
  --from=source \
  --to=deployment \
  --format=json \
  --output=provenance-graph.json

# Visualize the graph
provenance-linker visualize \
  --input=provenance-graph.json \
  --format=html \
  --output=supply-chain.html
```

#### Compliance Reports
```bash
# NIST SSDF compliance report
provenance-linker compliance nist-ssdf \
  --project=my-application \
  --output=nist-report.pdf

# EU CRA compliance documentation
provenance-linker compliance eu-cra \
  --project=my-application \
  --output=eu-cra-docs/
```

## Advanced Features

### SBOM Management

#### Generating SBOMs
```bash
# Generate comprehensive SBOM
provenance-linker sbom generate \
  --source=. \
  --format=cyclonedx \
  --include-dev-deps \
  --scan-licenses \
  --output=complete-sbom.json
```

#### SBOM Analysis
```bash
# Analyze SBOM for vulnerabilities
provenance-linker sbom analyze \
  --input=sbom.json \
  --check-vulnerabilities \
  --policy=security-policy.yaml \
  --output=analysis-report.html
```

#### Merging SBOMs
```bash
# Merge multiple SBOMs
provenance-linker sbom merge \
  --inputs=frontend.json,backend.json,database.json \
  --output=merged-sbom.json
```

### Policy-Based Verification

#### Creating Verification Policies
```yaml
# verification-policy.yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: my-app-policy
spec:
  images:
  - glob: "my-org/my-app:*"
    authorities:
    - key:
        data: |
          -----BEGIN PUBLIC KEY-----
          MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
          -----END PUBLIC KEY-----
    - keyless:
        identities:
        - issuer: https://accounts.google.com
          subject: release@my-org.com
```

#### Applying Policies
```bash
provenance-linker policy apply \
  --policy=verification-policy.yaml \
  --scope=production
```

### Vulnerability Management

#### Scanning for Vulnerabilities
```bash
# Scan artifact for vulnerabilities
provenance-linker scan \
  --artifact=my-app:v1.0.0 \
  --scanner=trivy \
  --output=vulnerability-report.json
```

#### Tracking Vulnerability Impact
```bash
# Find blast radius of a vulnerability
provenance-linker blast-radius \
  --vulnerability=CVE-2024-1234 \
  --include-transitive \
  --output=impact-analysis.json
```

## Integration Patterns

### CI/CD Integration

#### GitHub Actions
```yaml
# .github/workflows/provenance.yml
name: Provenance Tracking
on: [push, pull_request]

jobs:
  track-provenance:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Generate SBOM
      uses: anchore/sbom-action@v0
      with:
        output-file: sbom.spdx.json
    
    - name: Track Build Provenance
      run: |
        provenance-linker track build \
          --source-ref=${{ github.repository }}@${{ github.ref }} \
          --commit=${{ github.sha }} \
          --artifact=${{ env.IMAGE_NAME }}:${{ github.sha }} \
          --sbom=sbom.spdx.json \
          --build-system=github-actions \
          --build-id=${{ github.run_id }}
    
    - name: Sign Artifact
      run: |
        provenance-linker sign \
          --artifact=${{ env.IMAGE_NAME }}:${{ github.sha }} \
          --key-file=${{ secrets.COSIGN_PRIVATE_KEY }} \
          --annotations="workflow=${{ github.workflow }},run-id=${{ github.run_id }}"
```

#### GitLab CI
```yaml
# .gitlab-ci.yml
stages:
  - build
  - provenance

track_provenance:
  stage: provenance
  script:
    - provenance-linker track build \
        --source-ref=$CI_PROJECT_URL@$CI_COMMIT_REF_NAME \
        --commit=$CI_COMMIT_SHA \
        --artifact=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA \
        --sbom=sbom.json \
        --build-system=gitlab-ci \
        --build-id=$CI_PIPELINE_ID
```

### Kubernetes Integration

#### Admission Controller
```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionWebhook
metadata:
  name: provenance-validator
webhooks:
- name: validate-provenance.provenance-system.svc
  clientConfig:
    service:
      name: provenance-validator
      namespace: provenance-system
      path: "/validate"
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: ["apps"]
    apiVersions: ["v1"]
    resources: ["deployments"]
```

### API Integration

#### Go SDK Usage
```go
package main

import (
    "context"
    "github.com/your-org/provenance-linker/pkg/client"
    "github.com/your-org/provenance-linker/pkg/types"
)

func main() {
    client, err := client.New(client.Config{
        Endpoint: "http://provenance-service:8080",
        APIKey:   "your-api-key",
    })
    if err != nil {
        panic(err)
    }

    // Track build event
    err = client.TrackBuild(context.Background(), types.BuildEvent{
        SourceRef:    "git@github.com:org/repo.git@main",
        CommitHash:   "abc123def",
        BuildSystem:  "jenkins",
        BuildID:      "build-12345",
        Artifacts: []types.Artifact{
            {
                Name:    "my-service",
                Version: "v2.1.0",
                Type:    "container",
                Hash:    "sha256:abcdef...",
                SBOM:    sbomData,
            },
        },
    })
    if err != nil {
        panic(err)
    }
}
```

## Compliance Workflows

### NIST SSDF Compliance

1. **Configure SSDF Requirements**
   ```yaml
   # nist-ssdf-config.yaml
   framework: nist-ssdf
   version: "1.1"
   requirements:
     - id: "PO.1.1"
       description: "Define security requirements"
       evidence_required: true
     - id: "PS.1.1"
       description: "Protect source code"
       automated_check: true
   ```

2. **Generate Evidence**
   ```bash
   provenance-linker evidence collect \
     --framework=nist-ssdf \
     --project=my-application \
     --output=evidence/
   ```

3. **Generate Report**
   ```bash
   provenance-linker compliance report \
     --framework=nist-ssdf \
     --evidence-dir=evidence/ \
     --output=nist-ssdf-report.pdf
   ```

### EU CRA Compliance

1. **Risk Assessment**
   ```yaml
   # eu-cra-risk.yaml
   product:
     name: "My Application"
     category: "critical"
     cybersecurity_risk: "medium"
   
   components:
     - name: "web-frontend"
       risk_level: "low"
       security_measures:
         - "input_validation"
         - "output_encoding"
   ```

2. **Generate Documentation**
   ```bash
   provenance-linker compliance eu-cra \
     --product="My Application" \
     --risk-assessment=eu-cra-risk.yaml \
     --sbom=complete-sbom.json \
     --output=eu-cra-documentation/
   ```

## Troubleshooting

### Common Issues

#### Database Connection Problems
```bash
# Test database connectivity
provenance-linker health-check --verbose

# Check database status
neo4j status

# Verify credentials
provenance-linker config validate
```

#### SBOM Parsing Errors
```bash
# Validate SBOM format
provenance-linker sbom validate --input=sbom.json

# Debug parsing issues
provenance-linker sbom parse --input=sbom.json --debug
```

#### Signature Verification Failures
```bash
# Verify signing key
cosign verify-blob --key=cosign.pub --signature=artifact.sig artifact

# Check policy configuration
provenance-linker policy validate --policy=verification-policy.yaml
```

### Performance Optimization

#### Query Performance
- Use indexes on frequently queried properties
- Limit query depth for large graphs
- Use caching for repeated queries

#### Storage Optimization
- Regular database maintenance
- Archive old provenance data
- Optimize SBOM storage format

#### Network Optimization
- Use CDN for static assets
- Enable compression
- Configure connection pooling

### Support Channels

- **Documentation**: https://docs.your-org.com/provenance-linker
- **Community Forum**: https://community.your-org.com
- **GitHub Issues**: https://github.com/your-org/provenance-graph-sbom-linker/issues
- **Support Email**: support@your-org.com