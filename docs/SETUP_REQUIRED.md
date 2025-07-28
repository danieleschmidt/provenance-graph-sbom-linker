# Manual Setup Requirements

## GitHub Repository Settings

### Branch Protection Rules
Configure for `main` branch:
- [ ] Require pull request reviews (minimum 1)
- [ ] Require status checks to pass
- [ ] Restrict force pushes
- [ ] Require branches to be up to date

### Repository Secrets
Add in Settings > Secrets and variables > Actions:
- [ ] `DOCKER_HUB_TOKEN` - Container registry access
- [ ] `SECURITY_SCAN_TOKEN` - Security scanning tools
- [ ] `SLACK_WEBHOOK_URL` - Notifications (optional)

### Repository Topics
Add in repository Settings > General:
```
supply-chain, provenance, sbom, security, compliance, golang
```

## External Integrations

### Required Services
- [ ] **Docker Hub** - Container registry
- [ ] **Security Scanning** - Snyk/Trivy integration
- [ ] **Code Quality** - SonarCloud integration

### Optional Services
- [ ] **Monitoring** - Datadog/New Relic
- [ ] **Documentation** - GitHub Pages setup
- [ ] **Notifications** - Slack/Discord webhooks

## Command References

```bash
# Setup development environment
make setup

# Run quality checks
make lint test security-scan

# Build and deploy
make build docker-build
```

## Documentation Links

- [Contributing Guide](../CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)
- [Architecture Overview](../docs/ARCHITECTURE.md)