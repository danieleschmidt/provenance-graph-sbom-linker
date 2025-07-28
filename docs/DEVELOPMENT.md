# Development Guide

## Quick Setup

```bash
# Clone and setup
git clone <repository-url>
cd provenance-graph-sbom-linker
make setup

# Start development
make dev
```

## Prerequisites

- Go 1.21+
- Docker & Docker Compose  
- Make
- Git

## Development Commands

```bash
make build      # Build application
make test       # Run all tests
make lint       # Code quality checks
make format     # Format code
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system design.

## References

- [Contributing Guide](../CONTRIBUTING.md)
- [Go Style Guide](https://golang.org/doc/effective_go.html)
- [API Documentation](https://your-org.github.io/api-docs)