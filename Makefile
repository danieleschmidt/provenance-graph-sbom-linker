# Provenance Graph SBOM Linker - Makefile
# =============================================================================

# Variables
# =============================================================================
PROJECT_NAME := provenance-graph-sbom-linker
BINARY_NAME := provenance-linker
MODULE_NAME := github.com/danieleschmidt/provenance-graph-sbom-linker

# Go
GO := go
GOFMT := gofmt
GOLANGCI_LINT := golangci-lint
GOIMPORTS := goimports

# Directories
BUILD_DIR := bin
DIST_DIR := dist
DOCS_DIR := docs
TEST_DIR := test
COVERAGE_DIR := coverage

# Docker
DOCKER := docker
DOCKER_COMPOSE := docker-compose
REGISTRY := ghcr.io/danieleschmidt
IMAGE_NAME := $(REGISTRY)/$(PROJECT_NAME)

# Kubernetes
KUBECTL := kubectl
HELM := helm
NAMESPACE := provenance-system

# Build flags
VERSION := $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X $(MODULE_NAME)/internal/version.Version=$(VERSION) \
           -X $(MODULE_NAME)/internal/version.Commit=$(COMMIT) \
           -X $(MODULE_NAME)/internal/version.Date=$(DATE)

# Test flags
TEST_FLAGS := -v -race -count=1
INTEGRATION_TEST_FLAGS := $(TEST_FLAGS) -tags=integration
E2E_TEST_FLAGS := $(TEST_FLAGS) -tags=e2e
COVERAGE_FLAGS := -coverprofile=coverage.out -covermode=atomic

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[0;37m
RESET := \033[0m

# =============================================================================
# Help target
# =============================================================================

.PHONY: help
help: ## Show this help message
	@echo "$(CYAN)Provenance Graph SBOM Linker - Development Commands$(RESET)"
	@echo ""
	@echo "$(YELLOW)Usage:$(RESET)"
	@echo "  make <target>"
	@echo ""
	@echo "$(YELLOW)Targets:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# =============================================================================
# Development
# =============================================================================

.PHONY: setup
setup: ## Initial project setup
	@echo "$(BLUE)Setting up development environment...$(RESET)"
	$(GO) mod download
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install golang.org/x/tools/cmd/goimports@latest
	$(GO) install github.com/swaggo/swag/cmd/swag@latest
	$(GO) install github.com/golang/mock/mockgen@latest
	$(GO) install github.com/onsi/ginkgo/v2/ginkgo@latest
	@echo "$(GREEN)Setup complete!$(RESET)"

.PHONY: dev
dev: ## Start development environment
	@echo "$(BLUE)Starting development environment...$(RESET)"
	$(DOCKER_COMPOSE) -f docker-compose.dev.yml up -d
	@echo "$(GREEN)Development environment started!$(RESET)"
	@echo "Neo4j Browser: http://localhost:7474"
	@echo "Redis: localhost:6379"

.PHONY: dev-stop
dev-stop: ## Stop development environment
	@echo "$(BLUE)Stopping development environment...$(RESET)"
	$(DOCKER_COMPOSE) -f docker-compose.dev.yml down
	@echo "$(GREEN)Development environment stopped!$(RESET)"

.PHONY: dev-logs
dev-logs: ## Show development environment logs
	$(DOCKER_COMPOSE) -f docker-compose.dev.yml logs -f

.PHONY: clean
clean: ## Clean build artifacts and temporary files
	@echo "$(BLUE)Cleaning build artifacts...$(RESET)"
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -f coverage.out
	rm -f coverage.html
	$(GO) clean -cache -testcache -modcache
	@echo "$(GREEN)Clean complete!$(RESET)"

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build: ## Build the application
	@echo "$(BLUE)Building application...$(RESET)"
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server
	CGO_ENABLED=1 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-cli ./cmd/cli
	@echo "$(GREEN)Build complete! Binaries in $(BUILD_DIR)/$(RESET)"

.PHONY: build-race
build-race: ## Build with race detection
	@echo "$(BLUE)Building with race detection...$(RESET)"
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GO) build -race -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-race ./cmd/server
	@echo "$(GREEN)Race-enabled build complete!$(RESET)"

.PHONY: build-all
build-all: ## Build for all platforms
	@echo "$(BLUE)Building for all platforms...$(RESET)"
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/server
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/server
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/server
	@echo "$(GREEN)Multi-platform build complete! Binaries in $(DIST_DIR)/$(RESET)"

# =============================================================================
# Testing
# =============================================================================

.PHONY: test
test: ## Run all tests
	@echo "$(BLUE)Running all tests...$(RESET)"
	$(GO) test $(TEST_FLAGS) ./...
	@echo "$(GREEN)All tests passed!$(RESET)"

.PHONY: test-unit
test-unit: ## Run unit tests
	@echo "$(BLUE)Running unit tests...$(RESET)"
	$(GO) test $(TEST_FLAGS) ./pkg/... ./internal/...
	@echo "$(GREEN)Unit tests passed!$(RESET)"

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "$(BLUE)Running integration tests...$(RESET)"
	$(GO) test $(INTEGRATION_TEST_FLAGS) ./test/integration/...
	@echo "$(GREEN)Integration tests passed!$(RESET)"

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	@echo "$(BLUE)Running e2e tests...$(RESET)"
	$(GO) test $(E2E_TEST_FLAGS) ./test/e2e/...
	@echo "$(GREEN)E2E tests passed!$(RESET)"

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "$(BLUE)Running tests with coverage...$(RESET)"
	mkdir -p $(COVERAGE_DIR)
	$(GO) test $(TEST_FLAGS) $(COVERAGE_FLAGS) ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	$(GO) tool cover -func=coverage.out | tail -1
	@echo "$(GREEN)Coverage report generated: coverage.html$(RESET)"

.PHONY: test-watch
test-watch: ## Watch for changes and run tests
	@echo "$(BLUE)Watching for changes...$(RESET)"
	ginkgo watch -r --buildTags=unit

.PHONY: benchmark
benchmark: ## Run benchmarks
	@echo "$(BLUE)Running benchmarks...$(RESET)"
	$(GO) test -bench=. -benchmem ./...

# =============================================================================
# Code Quality
# =============================================================================

.PHONY: lint
lint: ## Run linters
	@echo "$(BLUE)Running linters...$(RESET)"
	$(GOLANGCI_LINT) run --timeout=5m
	@echo "$(GREEN)Linting complete!$(RESET)"

.PHONY: lint-fix
lint-fix: ## Run linters with auto-fix
	@echo "$(BLUE)Running linters with auto-fix...$(RESET)"
	$(GOLANGCI_LINT) run --fix --timeout=5m
	@echo "$(GREEN)Linting with fixes complete!$(RESET)"

.PHONY: format
format: ## Format code
	@echo "$(BLUE)Formatting code...$(RESET)"
	$(GOFMT) -s -w .
	$(GOIMPORTS) -w .
	@echo "$(GREEN)Formatting complete!$(RESET)"

.PHONY: vet
vet: ## Run go vet
	@echo "$(BLUE)Running go vet...$(RESET)"
	$(GO) vet ./...
	@echo "$(GREEN)Vet complete!$(RESET)"

.PHONY: security-scan
security-scan: ## Run security scans
	@echo "$(BLUE)Running security scans...$(RESET)"
	gosec ./...
	trivy fs --security-checks vuln .
	@echo "$(GREEN)Security scan complete!$(RESET)"

# =============================================================================
# Dependencies
# =============================================================================

.PHONY: deps-update
deps-update: ## Update dependencies
	@echo "$(BLUE)Updating dependencies...$(RESET)"
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "$(GREEN)Dependencies updated!$(RESET)"

.PHONY: deps-audit
deps-audit: ## Audit dependencies for vulnerabilities
	@echo "$(BLUE)Auditing dependencies...$(RESET)"
	$(GO) list -json -deps ./... | nancy sleuth
	@echo "$(GREEN)Dependency audit complete!$(RESET)"

.PHONY: deps-graph
deps-graph: ## Generate dependency graph
	@echo "$(BLUE)Generating dependency graph...$(RESET)"
	$(GO) mod graph | dot -T png -o deps-graph.png
	@echo "$(GREEN)Dependency graph generated: deps-graph.png$(RESET)"

# =============================================================================
# Documentation
# =============================================================================

.PHONY: docs
docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(RESET)"
	swag init -g cmd/server/main.go -o api/docs
	$(GO) doc -all > docs/godoc.txt
	@echo "$(GREEN)Documentation generated!$(RESET)"

.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	@echo "$(BLUE)Serving documentation...$(RESET)"
	godoc -http=:6060
	@echo "Documentation available at: http://localhost:6060"

# =============================================================================
# Docker
# =============================================================================

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(RESET)"
	$(DOCKER) build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .
	@echo "$(GREEN)Docker image built: $(IMAGE_NAME):$(VERSION)$(RESET)"

.PHONY: docker-push
docker-push: docker-build ## Push Docker image
	@echo "$(BLUE)Pushing Docker image...$(RESET)"
	$(DOCKER) push $(IMAGE_NAME):$(VERSION)
	$(DOCKER) push $(IMAGE_NAME):latest
	@echo "$(GREEN)Docker image pushed!$(RESET)"

.PHONY: docker-run
docker-run: ## Run Docker container locally
	@echo "$(BLUE)Running Docker container...$(RESET)"
	$(DOCKER) run --rm -p 8080:8080 $(IMAGE_NAME):latest

.PHONY: docker-scan
docker-scan: ## Scan Docker image for vulnerabilities
	@echo "$(BLUE)Scanning Docker image...$(RESET)"
	trivy image $(IMAGE_NAME):latest
	@echo "$(GREEN)Docker scan complete!$(RESET)"

# =============================================================================
# Kubernetes
# =============================================================================

.PHONY: k8s-deploy
k8s-deploy: ## Deploy to Kubernetes
	@echo "$(BLUE)Deploying to Kubernetes...$(RESET)"
	$(KUBECTL) apply -f deploy/kubernetes/
	@echo "$(GREEN)Deployed to Kubernetes!$(RESET)"

.PHONY: k8s-delete
k8s-delete: ## Delete from Kubernetes
	@echo "$(BLUE)Deleting from Kubernetes...$(RESET)"
	$(KUBECTL) delete -f deploy/kubernetes/
	@echo "$(GREEN)Deleted from Kubernetes!$(RESET)"

.PHONY: k8s-logs
k8s-logs: ## Show Kubernetes logs
	$(KUBECTL) logs -f deployment/$(PROJECT_NAME) -n $(NAMESPACE)

.PHONY: k8s-status
k8s-status: ## Show Kubernetes status
	$(KUBECTL) get all -n $(NAMESPACE)

# =============================================================================
# Helm
# =============================================================================

.PHONY: helm-install
helm-install: ## Install Helm chart
	@echo "$(BLUE)Installing Helm chart...$(RESET)"
	$(HELM) install $(PROJECT_NAME) ./charts/$(PROJECT_NAME) --namespace $(NAMESPACE) --create-namespace
	@echo "$(GREEN)Helm chart installed!$(RESET)"

.PHONY: helm-upgrade
helm-upgrade: ## Upgrade Helm chart
	@echo "$(BLUE)Upgrading Helm chart...$(RESET)"
	$(HELM) upgrade $(PROJECT_NAME) ./charts/$(PROJECT_NAME) --namespace $(NAMESPACE)
	@echo "$(GREEN)Helm chart upgraded!$(RESET)"

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall Helm chart
	@echo "$(BLUE)Uninstalling Helm chart...$(RESET)"
	$(HELM) uninstall $(PROJECT_NAME) --namespace $(NAMESPACE)
	@echo "$(GREEN)Helm chart uninstalled!$(RESET)"

.PHONY: helm-template
helm-template: ## Generate Helm templates
	$(HELM) template $(PROJECT_NAME) ./charts/$(PROJECT_NAME)

# =============================================================================
# Database
# =============================================================================

.PHONY: db-migrate
db-migrate: ## Run database migrations
	@echo "$(BLUE)Running database migrations...$(RESET)"
	$(GO) run ./cmd/migrate
	@echo "$(GREEN)Database migrations complete!$(RESET)"

.PHONY: db-seed
db-seed: ## Seed database with sample data
	@echo "$(BLUE)Seeding database...$(RESET)"
	$(GO) run ./cmd/seed
	@echo "$(GREEN)Database seeded!$(RESET)"

.PHONY: db-reset
db-reset: ## Reset database
	@echo "$(BLUE)Resetting database...$(RESET)"
	$(GO) run ./cmd/reset
	@echo "$(GREEN)Database reset!$(RESET)"

# =============================================================================
# Code Generation
# =============================================================================

.PHONY: generate
generate: ## Generate code (mocks, protobuf, etc.)
	@echo "$(BLUE)Generating code...$(RESET)"
	$(GO) generate ./...
	@echo "$(GREEN)Code generation complete!$(RESET)"

.PHONY: mock-generate
mock-generate: ## Generate mocks
	@echo "$(BLUE)Generating mocks...$(RESET)"
	find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" | xargs grep -l "//go:generate.*mockgen" | xargs -I {} $(GO) generate {}
	@echo "$(GREEN)Mock generation complete!$(RESET)"

.PHONY: proto-generate
proto-generate: ## Generate protobuf code
	@echo "$(BLUE)Generating protobuf code...$(RESET)"
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/proto/*.proto
	@echo "$(GREEN)Protobuf generation complete!$(RESET)"

# =============================================================================
# Release
# =============================================================================

.PHONY: pre-release
pre-release: clean lint test security-scan ## Run pre-release checks
	@echo "$(GREEN)Pre-release checks passed!$(RESET)"

.PHONY: release
release: pre-release build-all docker-build ## Create release
	@echo "$(BLUE)Creating release...$(RESET)"
	@echo "$(GREEN)Release $(VERSION) ready!$(RESET)"

# =============================================================================
# Monitoring
# =============================================================================

.PHONY: profile
profile: ## Run CPU profiling
	@echo "$(BLUE)Running CPU profiling...$(RESET)"
	$(GO) test -cpuprofile=cpu.prof -bench=. ./...
	$(GO) tool pprof cpu.prof

.PHONY: memory-profile
memory-profile: ## Run memory profiling
	@echo "$(BLUE)Running memory profiling...$(RESET)"
	$(GO) test -memprofile=mem.prof -bench=. ./...
	$(GO) tool pprof mem.prof

# =============================================================================
# Utility
# =============================================================================

.PHONY: version
version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Date: $(DATE)"

.PHONY: env
env: ## Show environment information
	@echo "$(CYAN)Environment Information:$(RESET)"
	@echo "Go version: $(shell $(GO) version)"
	@echo "Docker version: $(shell $(DOCKER) --version)"
	@echo "Kubectl version: $(shell $(KUBECTL) version --client --short 2>/dev/null || echo 'Not installed')"
	@echo "Helm version: $(shell $(HELM) version --short 2>/dev/null || echo 'Not installed')"

.PHONY: check-tools
check-tools: ## Check if required tools are installed
	@echo "$(BLUE)Checking required tools...$(RESET)"
	@which $(GO) > /dev/null || (echo "$(RED)Go not found$(RESET)" && exit 1)
	@which $(DOCKER) > /dev/null || (echo "$(RED)Docker not found$(RESET)" && exit 1)
	@which $(GOLANGCI_LINT) > /dev/null || (echo "$(YELLOW)golangci-lint not found, run 'make setup'$(RESET)")
	@echo "$(GREEN)All required tools are available!$(RESET)"

# Default target
.DEFAULT_GOAL := help