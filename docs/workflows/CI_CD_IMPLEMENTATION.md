# CI/CD Implementation Guide

This document provides comprehensive instructions for implementing GitHub Actions workflows for the Provenance Graph SBOM Linker project.

## Overview

The CI/CD pipeline implements:
- **Continuous Integration**: Automated testing, security scanning, and quality checks
- **Continuous Deployment**: Automated builds, container publishing, and deployment
- **Supply Chain Security**: SBOM generation, artifact signing, and attestation
- **Compliance**: NIST SSDF and EU CRA reporting

## Required GitHub Actions Workflows

### 1. Main CI Workflow (`.github/workflows/ci.yml`)

```yaml
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    name: Test
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go-version: ['1.21', '1.22']
        
    services:
      neo4j:
        image: neo4j:5.14-community
        env:
          NEO4J_AUTH: neo4j/testpassword
        ports:
          - 7687:7687
        options: >-
          --health-cmd "cypher-shell -u neo4j -p testpassword 'RETURN 1'"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0

    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: ${{ matrix.go-version }}

    - name: Cache Go modules
      uses: actions/cache@v3
      with:
        path: |
          ~/.cache/go-build
          ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ matrix.go-version }}-${{ hashFiles('**/go.sum') }}
        restore-keys: |
          ${{ runner.os }}-go-${{ matrix.go-version }}-

    - name: Download dependencies
      run: go mod download

    - name: Verify dependencies
      run: go mod verify

    - name: Run linting
      uses: golangci/golangci-lint-action@v3
      with:
        version: v1.55.2
        args: --timeout=5m

    - name: Run tests
      run: |
        make test-coverage
        
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
        flags: unittests
        name: codecov-umbrella

    - name: Run security scan
      uses: securecodewarrior/github-action-gosec@master
      with:
        args: ./...

  build:
    name: Build
    runs-on: ubuntu-latest
    needs: test
    
    steps:
    - uses: actions/checkout@v4

    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'

    - name: Build application
      run: make build

    - name: Upload build artifacts
      uses: actions/upload-artifact@v3
      with:
        name: binaries
        path: bin/
        retention-days: 30
```

### 2. Security Scanning Workflow (`.github/workflows/security.yml`)

```yaml
name: Security

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * 1'  # Weekly scan

jobs:
  vulnerability-scan:
    name: Vulnerability Scan
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4

    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'

    - name: Upload Trivy scan results to GitHub Security tab
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  secret-scan:
    name: Secret Scan
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4

    - name: Run GitLeaks
      uses: gitleaks/gitleaks-action@v2
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  dependency-review:
    name: Dependency Review
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Dependency Review
      uses: actions/dependency-review-action@v3
      with:
        fail-on-severity: high
```

### 3. Build and Release Workflow (`.github/workflows/release.yml`)

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write
  packages: write
  id-token: write

jobs:
  build-and-release:
    name: Build and Release
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0

    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'

    - name: Install Cosign
      uses: sigstore/cosign-installer@v3

    - name: Install Syft
      uses: anchore/sbom-action/download-syft@v0

    - name: Log in to GitHub Container Registry
      uses: docker/login-action@v3
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Build multi-platform binaries
      run: make build-all

    - name: Generate SBOM
      run: |
        syft packages . -o cyclonedx-json=sbom.cyclonedx.json
        syft packages . -o spdx-json=sbom.spdx.json

    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        platforms: linux/amd64,linux/arm64
        push: true
        tags: |
          ghcr.io/${{ github.repository_owner }}/provenance-graph-sbom-linker:${{ github.ref_name }}
          ghcr.io/${{ github.repository_owner }}/provenance-graph-sbom-linker:latest

    - name: Sign container image
      run: |
        cosign sign --yes ghcr.io/${{ github.repository_owner }}/provenance-graph-sbom-linker:${{ github.ref_name }}

    - name: Attest SBOM
      run: |
        cosign attest --yes --predicate sbom.cyclonedx.json --type cyclonedx \
          ghcr.io/${{ github.repository_owner }}/provenance-graph-sbom-linker:${{ github.ref_name }}

    - name: Create GitHub Release
      uses: softprops/action-gh-release@v1
      with:
        files: |
          dist/*
          sbom.*.json
        generate_release_notes: true
        draft: false
        prerelease: ${{ contains(github.ref_name, '-') }}
```

### 4. Performance Testing Workflow (`.github/workflows/performance.yml`)

```yaml
name: Performance

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 4 * * 1'  # Weekly performance test

jobs:
  benchmark:
    name: Benchmark
    runs-on: ubuntu-latest
    
    services:
      neo4j:
        image: neo4j:5.14-community
        env:
          NEO4J_AUTH: neo4j/testpassword
        ports:
          - 7687:7687
        options: >-
          --health-cmd "cypher-shell -u neo4j -p testpassword 'RETURN 1'"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v4

    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'

    - name: Run benchmarks
      run: |
        make benchmark > benchmark_results.txt
        cat benchmark_results.txt

    - name: Store benchmark result
      uses: benchmark-action/github-action-benchmark@v1
      with:
        tool: 'go'
        output-file-path: benchmark_results.txt
        github-token: ${{ secrets.GITHUB_TOKEN }}
        auto-push: ${{ github.ref == 'refs/heads/main' }}
        comment-on-alert: true
        alert-threshold: '200%'
        fail-on-alert: true

  load-test:
    name: Load Test
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    
    steps:
    - uses: actions/checkout@v4

    - name: Build application
      run: make build

    - name: Start application
      run: |
        ./bin/provenance-linker serve &
        sleep 10

    - name: Run load test
      run: |
        # Add load testing commands here
        echo "Load testing would be implemented here"

    - name: Collect metrics
      run: |
        # Collect performance metrics
        echo "Metrics collection would be implemented here"
```

## Required GitHub Secrets

Configure these secrets in your GitHub repository:

### Container Registry
- `GITHUB_TOKEN`: Automatically provided by GitHub

### Security Scanning
- `CODECOV_TOKEN`: For code coverage reporting
- `SNYK_TOKEN`: For Snyk vulnerability scanning (optional)

### Deployment (if needed)
- `KUBE_CONFIG`: Base64 encoded kubeconfig for deployment
- `DOCKER_REGISTRY`: Custom registry URL (if not using GHCR)
- `DOCKER_USERNAME`: Registry username
- `DOCKER_PASSWORD`: Registry password

### Signing Keys
- `COSIGN_PRIVATE_KEY`: Cosign private key for signing
- `COSIGN_PASSWORD`: Password for Cosign private key

## Implementation Steps

1. **Create Workflow Files**: Copy the above workflows to `.github/workflows/`
2. **Configure Secrets**: Add required secrets to GitHub repository settings
3. **Customize Configuration**: Adjust workflows for your specific needs
4. **Test Workflows**: Create a test branch and verify all workflows run correctly
5. **Monitor Results**: Set up notifications for workflow failures

## Branch Protection Rules

Configure these branch protection rules for `main`:

- Require pull request reviews before merging
- Require status checks to pass before merging:
  - `test` (Go 1.21, 1.22)
  - `build`
  - `vulnerability-scan`
  - `secret-scan`
- Require branches to be up to date before merging
- Require signed commits
- Include administrators in restrictions

## Workflow Optimization

### Caching Strategy
- Go modules cache reduces build time
- Docker layer caching for container builds
- Dependency cache for security scanning tools

### Parallel Execution
- Matrix builds for multiple Go versions
- Concurrent security scans
- Parallel container builds for multiple architectures

### Resource Management
- Use `concurrency` groups to cancel duplicate runs
- Optimize runner resource usage
- Implement proper cleanup for resources

## Monitoring and Alerting

### Workflow Notifications
Configure GitHub Actions to send notifications on:
- Workflow failures
- Security vulnerabilities
- Performance regressions
- Deployment status

### Metrics Collection
Track these metrics:
- Build success/failure rates
- Test coverage trends
- Security scan results
- Performance benchmark trends
- Deployment frequency and success rates

## Compliance and Auditing

### SLSA Compliance
- Generate SLSA provenance attestations
- Sign all artifacts with Cosign
- Maintain build transparency logs

### Audit Trail
- All builds are logged and traceable
- Artifact integrity verified with checksums
- Security scan results archived
- Compliance reports generated automatically

## Troubleshooting

### Common Issues
1. **Test Failures**: Check service health and database connections
2. **Build Failures**: Verify Go version compatibility and dependencies
3. **Security Scan Failures**: Review and address vulnerability findings
4. **Deployment Failures**: Check credentials and cluster connectivity

### Debug Steps
1. Enable debug logging in workflows
2. Use `tmate` action for interactive debugging
3. Check workflow run logs and artifacts
4. Verify secret configuration and permissions

## Next Steps

After implementing the basic workflows:

1. **Add Integration Tests**: Implement comprehensive end-to-end testing
2. **Performance Monitoring**: Set up continuous performance tracking
3. **Security Automation**: Implement automated security policy enforcement
4. **Deployment Automation**: Add staging and production deployment workflows
5. **Compliance Reporting**: Automated NIST SSDF and EU CRA report generation