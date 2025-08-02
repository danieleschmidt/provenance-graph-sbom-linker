# Test SBOM Fixtures

This directory contains test Software Bill of Materials (SBOM) files in various formats for testing and development.

## Directory Structure

```
sbom/
├── cyclonedx/              # CycloneDX format SBOMs
│   ├── simple.json         # Basic CycloneDX SBOM
│   ├── complex.json        # Complex SBOM with vulnerabilities
│   ├── go-project.json     # Go project SBOM example
│   ├── container.json      # Container image SBOM
│   └── invalid.json        # Invalid SBOM for error testing
├── spdx/                   # SPDX format SBOMs
│   ├── simple.json         # Basic SPDX SBOM
│   ├── complex.json        # Complex SPDX SBOM
│   ├── with-rels.json      # SBOM with relationships
│   └── package.spdx        # SPDX tag-value format
├── syft/                   # Syft format SBOMs
│   ├── alpine.json         # Alpine Linux base image
│   ├── ubuntu.json         # Ubuntu base image
│   └── scratch.json        # Scratch/distroless image
└── attestations/           # SBOM attestations
    ├── in-toto.json        # In-toto attestation format
    ├── slsa.json           # SLSA provenance with SBOM
    └── cosign.json         # Cosign attestation format
```

## Test Scenarios

### Valid SBOMs

These SBOMs are valid and can be used to test parsing and processing:

- **simple.json**: Minimal valid SBOM with a few components
- **complex.json**: Full-featured SBOM with vulnerabilities, licenses, and dependencies
- **go-project.json**: Realistic Go project with multiple dependencies
- **container.json**: Container image SBOM with OS packages and application libraries

### Invalid SBOMs

These SBOMs contain intentional errors for testing error handling:

- **invalid.json**: Malformed JSON structure
- **missing-required.json**: Missing required fields
- **invalid-version.json**: Unsupported format version

### Vulnerability Testing

Several SBOMs include vulnerability data for testing security features:

- Known CVEs with different severity levels
- Components with and without fixes available
- Transitive dependency vulnerabilities
- False positive scenarios

## Usage Examples

### Go Testing

```go
func TestSBOMParsing(t *testing.T) {
    // Load a test SBOM fixture
    data, err := os.ReadFile("test/fixtures/sbom/cyclonedx/simple.json")
    require.NoError(t, err)
    
    // Parse the SBOM
    sbom, err := parser.ParseCycloneDX(data)
    require.NoError(t, err)
    
    // Validate the SBOM structure
    assert.Equal(t, "CycloneDX", sbom.Format)
    assert.Equal(t, "1.4", sbom.Version)
    assert.NotEmpty(t, sbom.Components)
}
```

### CLI Testing

```bash
# Test SBOM parsing
./provenance-linker sbom parse test/fixtures/sbom/cyclonedx/simple.json

# Test vulnerability scanning
./provenance-linker sbom scan test/fixtures/sbom/cyclonedx/complex.json

# Test format conversion
./provenance-linker sbom convert \
  --input test/fixtures/sbom/cyclonedx/simple.json \
  --output-format spdx \
  --output simple.spdx.json
```

### Integration Testing

```bash
# Test full provenance flow with fixture SBOM
./provenance-linker track build \
  --source-ref git@github.com:test/repo.git@main \
  --commit abc123 \
  --artifact test-app:v1.0.0 \
  --sbom test/fixtures/sbom/cyclonedx/go-project.json
```

## Component Examples

### Common Component Types

The test SBOMs include examples of:

- **Operating System Packages**: Alpine APK, Ubuntu DEB packages
- **Language Libraries**: Go modules, npm packages, Python wheels
- **Container Images**: Base images, multi-stage builds
- **Application Code**: Source repositories, compiled binaries
- **Configuration Files**: Kubernetes manifests, Docker files

### License Examples

Various license scenarios are covered:

- **Permissive**: MIT, Apache-2.0, BSD-3-Clause
- **Copyleft**: GPL-3.0, LGPL-3.0, AGPL-3.0
- **Proprietary**: Commercial licenses
- **Unknown**: Components without license information
- **Multiple**: Components with multiple licenses

### Vulnerability Examples

Different vulnerability scenarios:

- **Critical**: RCE vulnerabilities (CVSS 9.0+)
- **High**: Privilege escalation (CVSS 7.0-8.9)
- **Medium**: Information disclosure (CVSS 4.0-6.9)
- **Low**: Minor issues (CVSS 1.0-3.9)
- **Disputed**: Vulnerabilities with disputed severity

## SBOM Validation

All fixture SBOMs are validated against their respective schemas:

- **CycloneDX**: [CycloneDX Schema](https://cyclonedx.org/schema/)
- **SPDX**: [SPDX Schema](https://github.com/spdx/spdx-spec)
- **Custom**: Internal validation rules

## Generating New Fixtures

To generate new test fixtures:

```bash
# Generate SBOM for current project
syft . -o cyclonedx-json > test/fixtures/sbom/cyclonedx/current-project.json

# Generate SBOM for container image
syft alpine:latest -o spdx-json > test/fixtures/sbom/spdx/alpine-latest.json

# Generate complex SBOM with vulnerabilities
grype alpine:latest -o cyclonedx > test/fixtures/sbom/cyclonedx/alpine-vulns.json
```

## Related Files

- `test/fixtures/certificates/`: Test certificates for signing SBOMs
- `test/fixtures/policies/`: Test policies for SBOM validation
- `test/testutil/factories.go`: SBOM factory functions for programmatic testing

## Compliance Testing

The fixtures support testing against various compliance frameworks:

- **NIST SSDF**: Software Supply Chain compliance
- **EU CRA**: Cyber Resilience Act requirements
- **SLSA**: Supply-chain Levels for Software Artifacts
- **In-toto**: Software supply chain integrity

## References

- [CycloneDX Specification](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [NIST SSDF Guidelines](https://csrc.nist.gov/Projects/ssdf)
- [SLSA Framework](https://slsa.dev/)