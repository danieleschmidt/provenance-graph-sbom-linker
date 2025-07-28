#!/bin/bash

# Post-create script for Provenance Graph SBOM Linker development environment

set -e

echo "🚀 Setting up Provenance Graph SBOM Linker development environment..."

# Update package lists
sudo apt-get update

# Install additional system dependencies
sudo apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    jq \
    unzip \
    ca-certificates \
    gnupg \
    lsb-release \
    graphviz \
    make

# Install Go tools
echo "📦 Installing Go development tools..."
go install -a github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install -a golang.org/x/tools/cmd/goimports@latest
go install -a github.com/swaggo/swag/cmd/swag@latest
go install -a github.com/golang/mock/mockgen@latest
go install -a github.com/onsi/ginkgo/v2/ginkgo@latest
go install -a github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
go install -a honnef.co/go/tools/cmd/staticcheck@latest
go install -a github.com/fzipp/gocyclo/cmd/gocyclo@latest

# Install Cosign for signature verification
echo "🔐 Installing Cosign..."
COSIGN_VERSION="v2.2.2"
wget "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign

# Install Syft for SBOM generation
echo "📋 Installing Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype for vulnerability scanning
echo "🔍 Installing Grype..."
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy for security scanning
echo "🛡️ Installing Trivy..."
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Install Python dependencies for SDK development
echo "🐍 Installing Python development tools..."
pip install --user \
    black \
    ruff \
    pytest \
    pytest-cov \
    mypy \
    requests \
    pydantic \
    typer \
    rich

# Install Node.js dependencies for dashboard
echo "🌐 Installing Node.js tools..."
npm install -g \
    typescript \
    @types/node \
    ts-node \
    prettier \
    eslint \
    @typescript-eslint/parser \
    @typescript-eslint/eslint-plugin \
    jest \
    @types/jest

# Create project directories
echo "📁 Creating project structure..."
mkdir -p {cmd,pkg,internal,api,web,deploy,scripts,test,docs/examples}
mkdir -p {pkg/{client,server,types,utils},internal/{auth,database,handlers,middleware}}
mkdir -p {test/{unit,integration,e2e},deploy/{kubernetes,docker}}

# Set up Git hooks directory
mkdir -p .githooks

# Install pre-commit framework
echo "🪝 Setting up pre-commit hooks..."
pip install --user pre-commit

# Initialize Go module if not exists
if [ ! -f "go.mod" ]; then
    echo "📦 Initializing Go module..."
    go mod init github.com/your-org/provenance-graph-sbom-linker
fi

# Create initial Go workspace
echo "🔧 Setting up Go workspace..."
cat > go.work <<EOF
go 1.21

use .
EOF

# Set up environment variables
echo "🌍 Setting up environment variables..."
cat > .env.example <<EOF
# Database Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=password
NEO4J_DATABASE=neo4j

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=

# API Configuration
API_PORT=8080
API_HOST=localhost
API_CORS_ORIGINS=http://localhost:3000

# Authentication
JWT_SECRET=your-jwt-secret-key
OIDC_ISSUER_URL=
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=

# Observability
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
PROMETHEUS_PORT=9090
JAEGER_ENDPOINT=http://localhost:14268/api/traces

# Storage
ARTIFACT_STORE_TYPE=filesystem
ARTIFACT_STORE_PATH=/tmp/artifacts
S3_BUCKET=
S3_REGION=
S3_ACCESS_KEY=
S3_SECRET_KEY=

# Security
COSIGN_PUBLIC_KEY_PATH=
SIGSTORE_ROOT_CA=
TUF_ROOT=

# Development
LOG_LEVEL=debug
DEV_MODE=true
EOF

# Set execute permissions for scripts
find scripts -type f -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

# Initialize Git configuration if needed
if [ ! -f ".git/config" ]; then
    echo "🔧 Initializing Git configuration..."
    git config --global init.defaultBranch main
    git config --global user.name "Development Container"
    git config --global user.email "dev@example.com"
fi

# Download and cache Go dependencies
echo "📥 Downloading Go dependencies..."
go mod download || echo "⚠️ Go modules not yet available, will download later"

# Set up development database (lightweight)
echo "🗄️ Setting up development environment..."
cat > docker-compose.dev.yml <<EOF
version: '3.8'
services:
  neo4j:
    image: neo4j:5.14-community
    environment:
      - NEO4J_AUTH=neo4j/password
      - NEO4J_PLUGINS=["graph-data-science"]
      - NEO4J_dbms_security_procedures_unrestricted=gds.*
    ports:
      - "7474:7474"
      - "7687:7687"
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs
    
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  neo4j_data:
  neo4j_logs:
  redis_data:
EOF

echo "✅ Development environment setup complete!"
echo ""
echo "🚀 Quick start commands:"
echo "  make dev        - Start development environment"
echo "  make test       - Run tests"
echo "  make build      - Build the application"
echo "  make lint       - Run linting"
echo "  make docs       - Generate documentation"
echo ""
echo "📖 Open README.md for detailed development instructions"