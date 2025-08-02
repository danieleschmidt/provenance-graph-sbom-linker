# Manual GitHub Workflows Setup Guide

Due to GitHub App permission limitations, the following workflows must be created manually by repository administrators. This guide provides step-by-step instructions for setting up the complete CI/CD pipeline.

## 🚨 Important Security Notice

**These workflows contain security-sensitive configurations. Ensure you:**
1. Review all workflow files before committing
2. Verify secret references match your organization's setup
3. Test workflows in a non-production environment first
4. Follow your organization's security approval process

## Prerequisites

### Required Permissions
- Repository admin access
- Ability to create GitHub Actions workflows
- Access to organization secrets (if applicable)

### Required Secrets
Configure these secrets in your repository settings (`Settings → Secrets and variables → Actions`):

#### Essential Secrets
```
COSIGN_PRIVATE_KEY        # Cosign private key for artifact signing
COSIGN_PASSWORD          # Password for Cosign private key
GITHUB_TOKEN             # Provided automatically by GitHub
```

#### Optional Secrets (based on integrations)
```
SEMGREP_APP_TOKEN        # Semgrep security scanning
FOSSA_API_KEY           # License compliance scanning
GITLEAKS_LICENSE        # GitLeaks Pro license
SONAR_TOKEN             # SonarCloud integration
SLACK_WEBHOOK_URL       # Notifications
KUBE_CONFIG             # Kubernetes deployment
REGISTRY_USERNAME       # Container registry (if not using GITHUB_TOKEN)
REGISTRY_PASSWORD       # Container registry credentials
```

## Step-by-Step Setup

### 1. Create Workflow Directory Structure

```bash
mkdir -p .github/workflows
mkdir -p .github/ISSUE_TEMPLATE
mkdir -p .github/PULL_REQUEST_TEMPLATE
```

### 2. Copy Workflow Templates

Copy the following template files from `docs/workflows/templates/` to `.github/workflows/`:

#### Core Workflows (Required)
1. **CI/CD Pipeline** - `ci.yml`
   ```bash
   cp docs/workflows/templates/ci.yml.template .github/workflows/ci.yml
   ```

2. **Security Scanning** - `security-scan.yml`
   ```bash
   cp docs/workflows/templates/security-scan.yml.template .github/workflows/security-scan.yml
   ```

3. **Dependency Updates** - `dependency-update.yml`
   ```bash
   cp docs/workflows/templates/dependency-update.yml.template .github/workflows/dependency-update.yml
   ```

#### Optional Workflows
4. **Release Automation** - `release.yml`
5. **Performance Testing** - `performance.yml`
6. **Container Scanning** - `container-scan.yml`

### 3. Customize Workflow Configuration

#### Update Registry Settings
Replace `ghcr.io/your-org` with your actual container registry:

```yaml
# In ci.yml and other workflow files
env:
  REGISTRY: ghcr.io/your-actual-org
  IMAGE_NAME: ${{ github.repository }}
```

#### Update Organization References
Replace placeholder values:
- `your-org` → Your actual GitHub organization name
- `Your Organization` → Your organization's display name
- Email addresses and contact information
- Notification endpoints (Slack, email, etc.)

#### Configure Branch Protection
In each workflow file, verify branch names match your strategy:
```yaml
on:
  push:
    branches: [ main, develop ]  # Adjust as needed
  pull_request:
    branches: [ main, develop ]  # Adjust as needed
```

### 4. Set Up Branch Protection Rules

Navigate to `Settings → Branches` and create protection rules:

#### For `main` branch:
```yaml
Required status checks:
  - Code Quality Analysis
  - Test Suite
  - Build Artifacts
  - Container Security Scan
  - Security Compliance

Restrictions:
  ✅ Require a pull request before merging
  ✅ Require approvals (minimum 1)
  ✅ Dismiss stale PR approvals when new commits are pushed
  ✅ Require review from code owners
  ✅ Restrict pushes that create files larger than 100MB
  ✅ Require branches to be up to date before merging
  ✅ Include administrators
```

#### For `develop` branch:
```yaml
Required status checks:
  - Test Suite
  - Build Artifacts
  - Security Compliance

Restrictions:
  ✅ Require a pull request before merging
  ✅ Require branches to be up to date before merging
```

### 5. Configure Security Settings

#### Enable Security Features
Go to `Settings → Security & analysis` and enable:
- ✅ Dependency graph
- ✅ Dependabot alerts
- ✅ Dependabot security updates
- ✅ Code scanning alerts
- ✅ Secret scanning alerts

#### Configure Dependabot
Create `.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "06:00"
    open-pull-requests-limit: 5
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"

  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    labels:
      - "dependencies"
      - "docker"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "monthly"
    open-pull-requests-limit: 2
    labels:
      - "dependencies"
      - "github-actions"
```

### 6. Create Required Scripts

Some workflows reference scripts that need to be created:

#### Compliance Validation Script
```bash
# Create scripts/validate-compliance.sh
cat > scripts/validate-compliance.sh << 'EOF'
#!/bin/bash
set -euo pipefail

FRAMEWORK="$1"

case "$FRAMEWORK" in
  "nist-ssdf")
    echo "Validating NIST SSDF compliance..."
    # Add your NIST SSDF validation logic
    ;;
  "eu-cra")
    echo "Validating EU CRA compliance..."
    # Add your EU CRA validation logic
    ;;
  *)
    echo "Unknown compliance framework: $FRAMEWORK"
    exit 1
    ;;
esac
EOF

chmod +x scripts/validate-compliance.sh
```

#### Smoke Tests Script
```bash
# Create scripts/smoke-tests.sh
cat > scripts/smoke-tests.sh << 'EOF'
#!/bin/bash
set -euo pipefail

ENDPOINT="$1"

echo "Running smoke tests against $ENDPOINT"

# Health check
curl -f "$ENDPOINT/health" || exit 1

# Version check
curl -f "$ENDPOINT/version" || exit 1

# Basic API test
curl -f "$ENDPOINT/api/v1/health" || exit 1

echo "Smoke tests passed!"
EOF

chmod +x scripts/smoke-tests.sh
```

### 7. Test Workflow Configuration

#### Validate Workflow Syntax
```bash
# Install act for local testing (optional)
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Validate workflow syntax
act --list
```

#### Test with Dry Run
1. Create a test branch
2. Make a small change
3. Push and observe workflow execution
4. Verify all steps complete successfully

### 8. Configure Notifications

#### Slack Integration (Optional)
If using Slack notifications, add webhook URL to secrets and update workflow files:

```yaml
- name: Notify Slack on failure
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: failure
    webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
```

#### Email Notifications
Configure email notifications in repository settings:
`Settings → Notifications → Email notifications`

### 9. Set Up Container Registry

#### GitHub Container Registry (Recommended)
1. Enable GitHub Container Registry for your organization
2. Configure package permissions
3. Update workflow registry settings

#### Alternative Registries
For Docker Hub, AWS ECR, or other registries:
1. Add authentication secrets
2. Update registry URLs in workflows
3. Configure push permissions

### 10. Monitoring and Maintenance

#### Regular Review Checklist
- [ ] Review workflow run history weekly
- [ ] Update dependencies in workflow files monthly
- [ ] Review and update secrets quarterly
- [ ] Audit permissions and access annually

#### Performance Optimization
- Monitor workflow execution times
- Optimize caching strategies
- Review resource usage
- Update runner specifications as needed

## Troubleshooting

### Common Issues

#### Secret Not Found
```
Error: Secret COSIGN_PRIVATE_KEY not found
```
**Solution**: Add the secret in repository settings

#### Permission Denied
```
Error: Resource not accessible by integration
```
**Solution**: Check workflow permissions and GitHub App permissions

#### Workflow Not Triggering
**Possible causes**:
- Branch protection blocking pushes
- Incorrect trigger configuration
- Workflow file syntax errors
- Repository permissions

#### Build Failures
**Debug steps**:
1. Check workflow logs
2. Verify environment variables
3. Test locally with same configuration
4. Check for dependency issues

### Getting Help

#### Internal Resources
- Contact your DevOps team
- Check organization documentation
- Review security team guidelines

#### External Resources
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Security Best Practices](https://docs.github.com/en/actions/security-guides)
- [Workflow Syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)

## Security Considerations

### Workflow Security
- **Never commit secrets to the repository**
- **Use environment-specific secrets**
- **Limit workflow permissions to minimum required**
- **Regularly audit and rotate secrets**
- **Monitor workflow execution for anomalies**

### Code Scanning
- **Enable all available security scanners**
- **Set appropriate failure thresholds**
- **Review and address security findings promptly**
- **Maintain security scanning baseline**

### Container Security
- **Scan all container images before deployment**
- **Use trusted base images only**
- **Implement image signing and verification**
- **Regular base image updates**

## Compliance Requirements

### NIST SSDF Compliance
The workflows implement NIST SSDF requirements:
- PS.1: Prepare the Organization
- PS.2: Protect the Software
- PS.3: Produce Well-Secured Software
- PW.1: Design Software Securely
- PW.2: Review the Software Design
- PW.3: Verify Third-party Software
- PW.4: Create Source Code
- PW.5: Create Software
- PW.6: Configure the Software
- PW.7: Review and/or Analyze the Software
- PW.8: Test the Software
- PW.9: Configure the Software for Deployment
- RV.1: Review, Analyze, and/or Test the Software
- RV.2: Assess and Analyze Vulnerabilities
- RV.3: Respond to Vulnerabilities

### EU Cyber Resilience Act
Workflows support EU CRA requirements for:
- Security by design
- Vulnerability handling
- Security updates
- Incident response
- Documentation and transparency

## Support and Maintenance

### Regular Updates
- Review and update workflows monthly
- Keep action versions current
- Update security scanning tools
- Refresh compliance requirements

### Monitoring
- Set up alerting for workflow failures
- Monitor security scan results
- Track compliance metrics
- Review performance trends

---

**Last Updated**: $(date)
**Version**: 1.0
**Maintained By**: DevOps Team

For questions or issues with this setup guide, please contact the DevOps team or create an issue in the repository.