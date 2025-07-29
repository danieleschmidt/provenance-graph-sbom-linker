# GitHub Workflows Implementation Guide

**Important**: Due to GitHub security policies, workflow files must be manually copied from the `workflows/` directory in this repository to `.github/workflows/` after the main pull request is merged.

## Required Workflow Files

The following workflow files have been prepared and should be copied to `.github/workflows/`:

### 1. Continuous Integration (`ci.yml`)
**Source**: `workflows/ci.yml`  
**Destination**: `.github/workflows/ci.yml`

**Features**:
- Multi-Go version testing (1.20, 1.21)
- Comprehensive security scanning (Gosec, Trivy)
- Integration testing with Neo4j and Redis services
- Code quality checks (golangci-lint, formatting)
- Coverage reporting with Codecov
- SBOM generation with multiple formats
- Container building and scanning

### 2. Security Scanning (`security.yml`)
**Source**: `workflows/security.yml`  
**Destination**: `.github/workflows/security.yml`

**Features**:
- Daily automated vulnerability scanning
- Dependency analysis with Nancy and Trivy
- Static security analysis with Gosec and Semgrep
- Container security scanning with multiple tools
- Secret detection with GitLeaks and TruffleHog
- License compliance checking
- SBOM security analysis

### 3. Release Automation (`release.yml`)
**Source**: `workflows/release.yml`  
**Destination**: `.github/workflows/release.yml`

**Features**:
- Multi-platform binary builds (Linux, macOS, Windows)
- Container image building with multi-arch support
- Cosign signing for all artifacts
- SBOM generation and attestation
- Automated GitHub releases with changelog
- Security validation before release

### 4. Performance Monitoring (`performance.yml`)
**Source**: `workflows/performance.yml`  
**Destination**: `.github/workflows/performance.yml`

**Features**:
- Comprehensive performance benchmarking
- Regression detection with baseline comparison
- Load testing with k6
- Memory and CPU profiling
- Performance trend analysis
- Automated PR comments with results

## Issue Templates

The following issue templates are ready to use:

### Bug Report Template
**Source**: `.github/ISSUE_TEMPLATE/bug_report.yml`  
**Status**: ✅ Already in place

### Feature Request Template
**Source**: `.github/ISSUE_TEMPLATE/feature_request.yml`  
**Status**: ✅ Already in place

### Security Report Template
**Source**: `.github/ISSUE_TEMPLATE/security_report.yml`  
**Status**: ✅ Already in place

## Pull Request Template

**Source**: `.github/PULL_REQUEST_TEMPLATE.md`  
**Status**: ✅ Already in place

## Dependabot Configuration

**Source**: `.github/dependabot.yml`  
**Status**: ✅ Already in place

## Manual Setup Instructions

### Step 1: Copy Workflow Files
```bash
# After merging the main PR, copy workflow files
cp workflows/ci.yml .github/workflows/
cp workflows/security.yml .github/workflows/
cp workflows/release.yml .github/workflows/
cp workflows/performance.yml .github/workflows/
```

### Step 2: Configure Secrets
Add the following secrets in GitHub repository settings:

- `CODECOV_TOKEN`: For code coverage reporting
- `GITLEAKS_LICENSE`: For GitLeaks Pro features (optional)

### Step 3: Configure Permissions
Ensure the following permissions are enabled for GitHub Actions:
- Contents: Read/Write (for releases)
- Security events: Write (for SARIF uploads)
- Packages: Write (for container registry)
- ID token: Write (for cosign signing)

### Step 4: Test Workflows
1. Create a test PR to verify CI workflow
2. Check security scans in the Security tab
3. Verify performance benchmarks run correctly
4. Test release workflow with a tag (optional)

## Workflow Dependencies

### External Services
- **Neo4j**: Required for integration tests
- **Redis**: Required for integration tests
- **Codecov**: For coverage reporting
- **GitHub Container Registry**: For container images

### Required Tools
- **Go 1.21+**: Primary development language
- **Docker**: For containerization and testing
- **k6**: For load testing (installed automatically)
- **cosign**: For artifact signing (installed automatically)

## Troubleshooting

### Common Issues

1. **Workflow file not found**
   - Ensure files are copied to `.github/workflows/`
   - Check file permissions and syntax

2. **Security scan failures**
   - Review SARIF uploads in Security tab
   - Check tool versions and configurations

3. **Performance benchmark timeouts**
   - Adjust timeout values in workflow
   - Check service startup times

4. **Release workflow failures**
   - Verify signing keys and permissions
   - Check multi-platform build compatibility

### Support

For workflow-related issues:
1. Check GitHub Actions logs for detailed error messages
2. Review workflow syntax with GitHub's workflow validator
3. Test locally with `act` or similar tools
4. Consult the project's governance documentation

## Security Considerations

- All workflows follow security best practices
- Secrets are properly scoped and protected
- Third-party actions are pinned to specific versions
- SARIF results are uploaded to GitHub Security tab
- Artifacts are signed with cosign for supply chain security

## Performance Impact

- CI workflow: ~15-20 minutes (with parallel execution)
- Security workflow: ~10-15 minutes (daily automated)
- Performance workflow: ~30-45 minutes (weekly scheduled)
- Release workflow: ~25-35 minutes (on tags only)

## Maintenance

- Review and update action versions quarterly
- Monitor workflow success rates and adjust as needed
- Update security scanning tools and rules regularly
- Review performance baselines and thresholds monthly