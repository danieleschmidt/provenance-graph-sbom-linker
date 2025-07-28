# Contributing to Provenance Graph SBOM Linker

Thank you for your interest in contributing to the Provenance Graph SBOM Linker! This document provides guidelines and information for contributors.

## 🎯 Quick Start

1. **Fork the repository** and clone your fork
2. **Set up the development environment** using the devcontainer or manual setup
3. **Create a feature branch** from `main`
4. **Make your changes** following our coding standards
5. **Run tests** and ensure they pass
6. **Submit a pull request** with a clear description

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security](#security)
- [Community](#community)

## 📜 Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## 🚀 Getting Started

### Prerequisites

- Go 1.21 or later
- Docker and Docker Compose
- Make
- Git

### Development Environment Setup

#### Option 1: DevContainer (Recommended)

1. Open the project in VS Code
2. Install the "Dev Containers" extension
3. Click "Reopen in Container" when prompted
4. The environment will be automatically set up

#### Option 2: Manual Setup

```bash
# Clone the repository
git clone https://github.com/your-org/provenance-graph-sbom-linker.git
cd provenance-graph-sbom-linker

# Set up the development environment
make setup

# Start development services
make dev
```

### Verify Installation

```bash
# Run tests to verify everything works
make test

# Build the application
make build

# Check code quality
make lint
```

## 🔄 Development Workflow

### Branching Strategy

We use the **GitHub Flow** branching model:

- `main` - Production-ready code
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `hotfix/*` - Critical production fixes

### Pull Request Process

1. **Create an Issue**: For significant changes, create an issue first to discuss the approach
2. **Create a Branch**: Create a feature branch from `main`
3. **Implement Changes**: Make your changes following our coding standards
4. **Add Tests**: Ensure your changes are thoroughly tested
5. **Update Documentation**: Update relevant documentation
6. **Run Pre-commit Hooks**: Ensure all checks pass
7. **Submit PR**: Create a pull request with a clear description

#### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

#### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes

#### Examples
```
feat(api): add SBOM validation endpoint

fix(database): resolve connection pool leak

docs(readme): update installation instructions

test(integration): add Neo4j connection tests
```

## 📏 Coding Standards

### Go Style Guide

We follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) and [Effective Go](https://golang.org/doc/effective_go.html).

#### Key Principles

1. **Simplicity**: Write simple, readable code
2. **Error Handling**: Always handle errors explicitly
3. **Documentation**: Document public APIs with godoc
4. **Naming**: Use clear, descriptive names
5. **Interfaces**: Keep interfaces small and focused

#### Code Formatting

```bash
# Format code
make format

# Run linter
make lint

# Fix linting issues
make lint-fix
```

### Project Structure

```
├── cmd/                    # Main applications
│   ├── server/            # API server
│   └── cli/               # CLI tool
├── pkg/                   # Public library code
│   ├── client/            # Client libraries
│   ├── types/             # Type definitions
│   └── utils/             # Utility functions
├── internal/              # Private application code
│   ├── auth/              # Authentication
│   ├── database/          # Database layer
│   ├── handlers/          # HTTP handlers
│   └── middleware/        # HTTP middleware
├── test/                  # Test files
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── e2e/               # End-to-end tests
├── docs/                  # Documentation
├── deploy/                # Deployment configurations
└── scripts/               # Build and utility scripts
```

### API Design Guidelines

1. **RESTful**: Follow REST principles
2. **Versioning**: Use URL versioning (e.g., `/api/v1/`)
3. **Status Codes**: Use appropriate HTTP status codes
4. **Error Responses**: Consistent error response format
5. **Pagination**: Use cursor-based pagination for large datasets

#### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid SBOM format",
    "details": {
      "field": "format",
      "value": "invalid"
    },
    "timestamp": "2024-01-20T10:30:00Z",
    "trace_id": "abc123"
  }
}
```

## 🧪 Testing Guidelines

### Testing Philosophy

- **Test Pyramid**: More unit tests, fewer integration tests, minimal E2E tests
- **Test Coverage**: Aim for >80% coverage
- **Fast Feedback**: Tests should run quickly
- **Isolation**: Tests should be independent

### Test Categories

#### Unit Tests
```bash
# Run unit tests
make test-unit

# Run with coverage
make test-coverage
```

#### Integration Tests
```bash
# Run integration tests (requires Docker)
make test-integration
```

#### End-to-End Tests
```bash
# Run E2E tests
make test-e2e
```

### Writing Tests

#### Unit Test Example
```go
func TestValidateSBOM(t *testing.T) {
    tests := []struct {
        name    string
        sbom    *SBOM
        wantErr bool
    }{
        {
            name: "valid SBOM",
            sbom: &SBOM{
                Format:  "CycloneDX",
                Version: "1.4",
            },
            wantErr: false,
        },
        {
            name: "invalid format",
            sbom: &SBOM{
                Format: "invalid",
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateSBOM(tt.sbom)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateSBOM() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Test Data Management

- Use test fixtures in `test/fixtures/`
- Clean up test data after tests
- Use factories for complex test data

## 📖 Documentation

### Types of Documentation

1. **Code Documentation**: Godoc comments
2. **API Documentation**: OpenAPI/Swagger specs
3. **User Documentation**: README, usage guides
4. **Developer Documentation**: Architecture, contributing guides

### Documentation Standards

#### Godoc Comments
```go
// ValidateSBOM validates an SBOM according to the specified format.
// It returns an error if the SBOM is invalid or unsupported.
//
// Supported formats:
//   - CycloneDX (versions 1.3, 1.4, 1.5)
//   - SPDX (versions 2.2, 2.3)
//
// Example:
//   sbom := &SBOM{Format: "CycloneDX", Version: "1.4"}
//   err := ValidateSBOM(sbom)
func ValidateSBOM(sbom *SBOM) error {
    // Implementation
}
```

#### API Documentation
- Use OpenAPI 3.0 specifications
- Include examples for all endpoints
- Document error responses

### Building Documentation

```bash
# Generate API docs
make api:docs

# Generate and serve documentation
make docs-serve
```

## 🔒 Security

### Security Guidelines

1. **No Secrets**: Never commit secrets or keys
2. **Input Validation**: Validate all inputs
3. **Error Handling**: Don't expose sensitive information in errors
4. **Dependencies**: Keep dependencies updated
5. **Authentication**: Use secure authentication methods

### Security Testing

```bash
# Run security scans
make security-scan

# Check for vulnerabilities
make deps-audit
```

### Reporting Security Issues

Please report security vulnerabilities to security@your-org.com. Do not create public issues for security vulnerabilities.

## 🏗️ Architecture Decisions

### Making Architecture Decisions

For significant architectural changes:

1. **Create an ADR**: Use the Architecture Decision Record template
2. **Discuss in Issues**: Create an issue for discussion
3. **Seek Consensus**: Get agreement from maintainers
4. **Document**: Update architecture documentation

### ADR Template

Create new ADRs in `docs/adr/` following the format:

```markdown
# ADR-XXXX: Title

## Status
[Proposed | Accepted | Deprecated | Superseded]

## Context
Description of the problem and context

## Decision
The decision made

## Consequences
Expected consequences of the decision
```

## 🌟 Recognition

### Contributors

We recognize contributions in several ways:

- **GitHub Contributors**: Listed automatically on GitHub
- **Release Notes**: Significant contributions mentioned in releases
- **All Contributors**: Using the All Contributors specification

### Types of Contributions

We value all types of contributions:

- 🐛 Bug reports and fixes
- ✨ Feature development
- 📖 Documentation improvements
- 🧪 Testing and quality assurance
- 🔍 Code reviews
- 💬 Community support
- 🎨 Design and UX improvements

## 📞 Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Discord**: Real-time community chat
- **Email**: supply-chain@your-org.com

### Maintainer Response Times

- **Critical Security Issues**: Within 24 hours
- **Bug Reports**: Within 1 week
- **Feature Requests**: Within 2 weeks
- **Pull Requests**: Within 1 week

### Office Hours

Join our weekly office hours for real-time discussion:
- **When**: Fridays 3:00-4:00 PM UTC
- **Where**: Discord voice channel
- **What**: Q&A, design discussions, community updates

## 📜 License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## 🙏 Thank You

Thank you for contributing to the Provenance Graph SBOM Linker! Your contributions help make software supply chains more secure for everyone.

---

*This document is living and will be updated as the project evolves. Please suggest improvements!*