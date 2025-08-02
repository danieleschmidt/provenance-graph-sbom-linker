# Required Manual Setup Actions

Due to GitHub App permission limitations, the following actions must be performed manually by repository administrators to complete the SDLC implementation.

## 🚨 Critical Actions Required

### 1. GitHub Actions Workflows Setup
**Priority**: HIGH | **Time Required**: 30-45 minutes

#### Actions:
1. Copy workflow templates from `docs/workflows/templates/` to `.github/workflows/`
2. Configure required secrets in repository settings
3. Set up branch protection rules
4. Test workflow execution

#### Files to Copy:
```bash
cp docs/workflows/templates/ci.yml.template .github/workflows/ci.yml
cp docs/workflows/templates/security-scan.yml.template .github/workflows/security-scan.yml
cp docs/workflows/templates/dependency-update.yml.template .github/workflows/dependency-update.yml
```

#### Required Secrets:
- `COSIGN_PRIVATE_KEY` - For artifact signing
- `COSIGN_PASSWORD` - Password for Cosign key
- Additional secrets based on integrations (see setup guide)

**📖 Detailed Guide**: `docs/workflows/MANUAL_SETUP_GUIDE.md`

### 2. Branch Protection Configuration
**Priority**: HIGH | **Time Required**: 10 minutes

#### Required Settings:
- Enable required status checks for all security scans
- Require pull request reviews (minimum 1)
- Require branches to be up to date
- Include administrators in restrictions

**Location**: Repository Settings → Branches

### 3. Security Features Activation
**Priority**: HIGH | **Time Required**: 5 minutes

#### Enable:
- Dependency graph
- Dependabot alerts
- Dependabot security updates
- Code scanning alerts
- Secret scanning alerts

**Location**: Repository Settings → Security & analysis

### 4. Container Registry Setup
**Priority**: MEDIUM | **Time Required**: 15 minutes

#### Actions:
- Configure GitHub Container Registry permissions
- Set up authentication for container pushes
- Update registry URLs in workflow files

### 5. Team Permissions Configuration
**Priority**: MEDIUM | **Time Required**: 10 minutes

#### Configure:
- Security team access to security-related files
- Platform team access to infrastructure components
- Development team standard access

**Reference**: `.github/CODEOWNERS`

## 📋 Validation Checklist

After completing manual setup, verify:

- [ ] Workflows execute successfully on test branch
- [ ] Security scans run and report results
- [ ] Artifact signing works correctly
- [ ] Branch protection prevents unauthorized changes
- [ ] Container builds and pushes successfully
- [ ] Notifications work as expected
- [ ] All team members have appropriate access

## Repository Topics
Add in repository Settings > General:
```
supply-chain, provenance, sbom, security, compliance, golang, slsa, nist-ssdf, eu-cra, sigstore, cosign
```

## Command References

```bash
# Setup development environment
make setup

# Run comprehensive build with security
./scripts/build.sh --test --security-scan --sign

# Run quality checks
make lint test security-scan

# Build and deploy
make build docker-build
```

## 🔗 Resources

- **Complete Setup Guide**: `docs/workflows/MANUAL_SETUP_GUIDE.md`
- **Implementation Summary**: `IMPLEMENTATION_SUMMARY.md`
- **Architecture Documentation**: `docs/ARCHITECTURE.md`
- **Troubleshooting**: Contact DevOps team

## ⏰ Estimated Total Setup Time

- **Minimum Setup**: 1 hour (core workflows only)
- **Complete Setup**: 2-3 hours (all features)
- **Team Training**: 1-2 hours (onboarding)

## 🆘 Support

For assistance with manual setup:
1. Review the detailed setup guide
2. Contact the DevOps team
3. Create an issue for specific problems
4. Schedule team training session

## Documentation Links

- [Contributing Guide](../CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)
- [Architecture Overview](ARCHITECTURE.md)
- [Manual Setup Guide](workflows/MANUAL_SETUP_GUIDE.md)