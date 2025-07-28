# Quick Start Guide

Get up and running with Provenance Graph SBOM Linker in under 10 minutes.

## Prerequisites

- Go 1.21 or later
- Docker and Docker Compose
- Git
- Make (optional, but recommended)

## Installation

### Option 1: Binary Installation (Recommended)

```bash
# Download the latest release
curl -L https://github.com/your-org/provenance-graph-sbom-linker/releases/latest/download/provenance-linker_$(uname -s)_$(uname -m).tar.gz | tar xz

# Move to PATH
sudo mv provenance-linker /usr/local/bin/

# Verify installation
provenance-linker version
```

### Option 2: From Source

```bash
# Clone the repository
git clone https://github.com/your-org/provenance-graph-sbom-linker.git
cd provenance-graph-sbom-linker

# Build the binary
make build

# Install locally
sudo mv bin/provenance-linker /usr/local/bin/
```

### Option 3: Docker

```bash
# Pull the image
docker pull your-org/provenance-linker:latest

# Create an alias for convenience
echo 'alias provenance-linker="docker run --rm -v $(pwd):/workspace your-org/provenance-linker:latest"' >> ~/.bashrc
source ~/.bashrc
```

## Basic Usage

### 1. Initialize a Project

```bash
# Initialize provenance tracking for your project
provenance-linker init --project my-awesome-app

# This creates a .provenance.yaml configuration file
```

### 2. Track Your First Build

```bash
# Track a simple build
provenance-linker track build \
  --source-ref=git@github.com:myorg/my-app.git@main \
  --commit=$(git rev-parse HEAD) \
  --artifact=my-app:v1.0.0 \
  --sbom=sbom.cyclonedx.json
```

### 3. Generate an SBOM

```bash
# Generate SBOM for your project
provenance-linker sbom generate \
  --source=. \
  --format=cyclonedx \
  --output=sbom.json
```

### 4. Sign Your Artifact

```bash
# Sign with Cosign (requires cosign to be installed)
provenance-linker sign \
  --artifact=my-app:v1.0.0 \
  --key=cosign.key
```

### 5. Verify the Supply Chain

```bash
# Verify the complete supply chain
provenance-linker verify \
  --artifact=my-app:v1.0.0 \
  --policy=verification-policy.yaml
```

### 6. Generate a Provenance Graph

```bash
# Create a visual representation of your supply chain
provenance-linker graph \
  --from=source \
  --to=deployment \
  --output=provenance-graph.json

# Visualize it
provenance-linker visualize \
  --input=provenance-graph.json \
  --format=html \
  --output=supply-chain.html
```

## Integration Examples

### GitHub Actions

```yaml
# .github/workflows/build.yml
name: Build and Track Provenance

on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
          
      - name: Build application
        run: go build -o app .
        
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          output-file: sbom.spdx.json
          
      - name: Track Provenance
        run: |
          provenance-linker track build \
            --source-ref=${{ github.repository }}@${{ github.ref_name }} \
            --commit=${{ github.sha }} \
            --artifact=my-app:${{ github.ref_name }} \
            --sbom=sbom.spdx.json
```

### Docker Build

```bash
# Build with provenance tracking
docker build -t my-app:latest .

# Generate SBOM for the container
provenance-linker sbom generate \
  --source=docker://my-app:latest \
  --format=cyclonedx \
  --output=container-sbom.json

# Track the container build
provenance-linker track build \
  --source-ref=git@github.com:myorg/my-app.git@main \
  --commit=$(git rev-parse HEAD) \
  --artifact=docker://my-app:latest \
  --sbom=container-sbom.json
```

### Kubernetes Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  annotations:
    provenance.linker/source-ref: "git@github.com:myorg/my-app.git@v1.0.0"
    provenance.linker/commit: "abc123def456"
    provenance.linker/sbom: "sha256:def789ghi012"
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    spec:
      containers:
      - name: my-app
        image: my-app:v1.0.0
```

```bash
# Track the deployment
kubectl apply -f deployment.yaml

provenance-linker track deployment \
  --artifact=docker://my-app:v1.0.0 \
  --deployment=k8s://default/my-app \
  --verify-signatures
```

## Configuration

### Basic Configuration File

Create `.provenance.yaml` in your project root:

```yaml
project:
  name: "my-awesome-app"
  version: "1.0"
  
source:
  type: "git"
  url: "https://github.com/myorg/my-app"
  
build:
  system: "github-actions"
  workflow: ".github/workflows/build.yml"
  
artifacts:
  - name: "binary"
    type: "executable"
    path: "./app"
    
  - name: "container"
    type: "docker"
    registry: "ghcr.io/myorg"
    
sbom:
  format: "cyclonedx"
  include-dev-deps: false
  
signing:
  enabled: true
  algorithm: "cosign"
  key-path: "cosign.key"
```

### Environment Variables

```bash
# Core configuration
export PROVENANCE_ENDPOINT="http://localhost:8080"
export PROVENANCE_API_KEY="your-api-key"

# Database configuration
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USERNAME="neo4j"
export NEO4J_PASSWORD="password"

# Signing configuration
export COSIGN_PRIVATE_KEY_PATH="/path/to/cosign.key"
export COSIGN_PASSWORD="your-password"
```

## Next Steps

### For Developers
1. **Explore the API**: Check out the [API Documentation](../api/README.md)
2. **SDK Integration**: Use our [Go SDK](../sdk/go.md) or [Python SDK](../sdk/python.md)
3. **CI/CD Integration**: Set up automated tracking in your build pipelines

### For Security Teams
1. **Policy Configuration**: Define verification policies for your organization
2. **Vulnerability Monitoring**: Set up automated vulnerability correlation
3. **Compliance Reporting**: Configure NIST SSDF and EU CRA reporting

### For Operations Teams
1. **Production Deployment**: Deploy the service in your infrastructure
2. **Monitoring Setup**: Configure observability and alerting
3. **Backup and Recovery**: Implement data protection strategies

## Troubleshooting

### Common Issues

#### Command Not Found
```bash
# Verify installation
which provenance-linker

# Check PATH
echo $PATH

# Reinstall if necessary
curl -L https://github.com/your-org/provenance-graph-sbom-linker/releases/latest/download/provenance-linker_$(uname -s)_$(uname -m).tar.gz | tar xz
sudo mv provenance-linker /usr/local/bin/
```

#### Database Connection Failed
```bash
# Check Neo4j is running
docker ps | grep neo4j

# Start Neo4j if needed
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:latest

# Test connection
provenance-linker health-check
```

#### Permission Denied
```bash
# Fix file permissions
chmod +x /usr/local/bin/provenance-linker

# Or run with sudo
sudo provenance-linker --help
```

### Getting Help

- **Documentation**: [Full Documentation](../README.md)
- **Issues**: [GitHub Issues](https://github.com/your-org/provenance-graph-sbom-linker/issues)
- **Community**: [Discord Channel](https://discord.gg/your-org)
- **Support**: supply-chain@your-org.com

## What's Next?

Now that you have the basics working, explore these advanced features:

- [ML Model Tracking](ml-models.md)
- [Multi-Cloud Deployment](deployment.md)
- [Advanced Visualization](visualization.md)
- [Custom Compliance Frameworks](compliance.md)
- [Federation Setup](federation.md)

Welcome to secure supply chain management! 🔐