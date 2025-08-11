#!/bin/bash
set -euo pipefail

# Production Deployment Script for Provenance Linker
# Usage: ./scripts/deploy.sh [environment] [version]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="${1:-production}"
VERSION="${2:-latest}"
DEPLOY_DIR="$PROJECT_ROOT/deploy/$ENVIRONMENT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Docker is installed and running
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if deployment directory exists
    if [[ ! -d "$DEPLOY_DIR" ]]; then
        log_error "Deployment directory not found: $DEPLOY_DIR"
        exit 1
    fi
    
    # Check if .env file exists
    if [[ ! -f "$DEPLOY_DIR/.env" ]]; then
        log_warning ".env file not found in $DEPLOY_DIR"
        log_info "Please copy .env.example to .env and configure it"
        if [[ -f "$DEPLOY_DIR/.env.example" ]]; then
            log_info "Example: cp $DEPLOY_DIR/.env.example $DEPLOY_DIR/.env"
        fi
        exit 1
    fi
    
    log_success "Prerequisites check completed"
}

# Build application images
build_images() {
    log_info "Building application images..."
    
    cd "$PROJECT_ROOT"
    
    # Build production image
    docker build \
        --build-arg GIT_COMMIT="$(git rev-parse HEAD)" \
        --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --build-arg VERSION="$VERSION" \
        -f Dockerfile.prod \
        -t "provenance-linker:$VERSION" \
        -t "provenance-linker:latest" \
        .
    
    log_success "Images built successfully"
}

# Run security scan on images
security_scan() {
    log_info "Running security scan on images..."
    
    # Using Docker's built-in scan if available
    if command -v docker scan &> /dev/null; then
        docker scan "provenance-linker:$VERSION" || log_warning "Security scan found issues"
    else
        log_warning "Docker scan not available, skipping security scan"
    fi
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run Go tests
    if command -v go &> /dev/null; then
        go test ./... -v -cover || {
            log_error "Tests failed"
            exit 1
        }
    else
        log_warning "Go not available, running tests in Docker"
        docker run --rm \
            -v "$PROJECT_ROOT:/app" \
            -w /app \
            golang:1.23 \
            go test ./... -v -cover || {
            log_error "Tests failed"
            exit 1
        }
    fi
    
    log_success "Tests passed"
}

# Deploy application
deploy() {
    log_info "Deploying to $ENVIRONMENT environment..."
    
    cd "$DEPLOY_DIR"
    
    # Pull latest images for dependencies
    docker-compose -f docker-compose.prod.yml pull
    
    # Stop existing containers gracefully
    docker-compose -f docker-compose.prod.yml down --timeout 30
    
    # Start services
    docker-compose -f docker-compose.prod.yml up -d
    
    # Wait for services to be healthy
    wait_for_health
    
    log_success "Deployment completed successfully"
}

# Wait for services to be healthy
wait_for_health() {
    log_info "Waiting for services to be healthy..."
    
    local max_attempts=30
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if curl -f -s http://localhost:8080/health/live &> /dev/null; then
            log_success "Application is healthy"
            return 0
        fi
        
        attempt=$((attempt + 1))
        log_info "Health check attempt $attempt/$max_attempts..."
        sleep 10
    done
    
    log_error "Application failed to become healthy"
    docker-compose -f docker-compose.prod.yml logs --tail=50
    exit 1
}

# Backup current state
backup() {
    log_info "Creating backup..."
    
    local backup_dir="/var/backups/provenance-linker/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup Neo4j data
    if docker ps | grep -q provenance-neo4j; then
        docker exec provenance-neo4j neo4j-admin dump --database=neo4j --to=/tmp/neo4j-backup.dump
        docker cp provenance-neo4j:/tmp/neo4j-backup.dump "$backup_dir/neo4j-backup.dump"
    fi
    
    # Backup Redis data
    if docker ps | grep -q provenance-redis; then
        docker exec provenance-redis redis-cli BGSAVE
        docker cp provenance-redis:/data/dump.rdb "$backup_dir/redis-backup.rdb"
    fi
    
    log_success "Backup created at $backup_dir"
}

# Rollback deployment
rollback() {
    log_warning "Rolling back deployment..."
    
    cd "$DEPLOY_DIR"
    
    # Stop current services
    docker-compose -f docker-compose.prod.yml down --timeout 30
    
    # Use previous version (this is simplified - in production, you'd have versioned images)
    docker-compose -f docker-compose.prod.yml up -d
    
    log_success "Rollback completed"
}

# Monitor deployment
monitor() {
    log_info "Monitoring deployment..."
    
    # Show logs
    cd "$DEPLOY_DIR"
    docker-compose -f docker-compose.prod.yml logs -f --tail=100
}

# Clean up old images and containers
cleanup() {
    log_info "Cleaning up old images and containers..."
    
    # Remove stopped containers
    docker container prune -f
    
    # Remove unused images (keep last 3 versions)
    docker images "provenance-linker" --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}" | \
        grep -v "latest" | tail -n +4 | awk '{print $1}' | xargs -r docker rmi
    
    # Remove unused volumes (be careful with this in production)
    # docker volume prune -f
    
    log_success "Cleanup completed"
}

# Main deployment flow
main() {
    log_info "Starting deployment of Provenance Linker v$VERSION to $ENVIRONMENT"
    
    case "${3:-deploy}" in
        "build")
            check_prerequisites
            build_images
            ;;
        "test")
            run_tests
            ;;
        "deploy")
            check_prerequisites
            build_images
            security_scan
            run_tests
            backup
            deploy
            ;;
        "rollback")
            rollback
            ;;
        "monitor")
            monitor
            ;;
        "cleanup")
            cleanup
            ;;
        "health")
            wait_for_health
            ;;
        *)
            log_info "Usage: $0 [environment] [version] [action]"
            log_info "Actions: build, test, deploy, rollback, monitor, cleanup, health"
            exit 1
            ;;
    esac
}

# Trap signals for graceful shutdown
trap 'log_error "Deployment interrupted"; exit 1' INT TERM

# Run main function
main "$@"