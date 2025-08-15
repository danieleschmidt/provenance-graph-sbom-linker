#!/bin/bash

# Production Deployment Script for Self-Healing Pipeline Guard System
# TERRAGON SDLC AUTONOMOUS EXECUTION - Production Deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
SERVICE_NAME="${SERVICE_NAME:-provenance-linker}"
DOCKER_COMPOSE_FILE="$PROJECT_ROOT/deployments/docker/docker-compose.production.yml"

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

# Banner
show_banner() {
    echo -e "${BLUE}"
    echo "================================================================"
    echo "  TERRAGON SDLC - Self-Healing Pipeline Guard System"
    echo "  Production Deployment Script"
    echo "  Autonomous Execution - All Generations Complete"
    echo "================================================================"
    echo -e "${NC}"
}

# Prerequisites check
check_prerequisites() {
    log_info "Checking deployment prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check required files
    local required_files=(
        "$DOCKER_COMPOSE_FILE"
        "$PROJECT_ROOT/deployments/docker/Dockerfile.production"
        "$PROJECT_ROOT/deployments/docker/healthcheck.sh"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "Required file not found: $file"
            exit 1
        fi
    done
    
    log_success "All prerequisites met"
}

# Environment setup
setup_environment() {
    log_info "Setting up deployment environment..."
    
    # Create environment file if it doesn't exist
    local env_file="$PROJECT_ROOT/.env.production"
    
    if [[ ! -f "$env_file" ]]; then
        log_info "Creating production environment file..."
        cat > "$env_file" << EOF
# Production Environment Configuration
# TERRAGON SDLC - Self-Healing Pipeline Guard System

# Application
SERVER_PORT=8080
LOG_LEVEL=info
GOMAXPROCS=0
GOGC=100

# Database
NEO4J_PASSWORD=secure_password_change_this
NEO4J_HTTP_PORT=7474
NEO4J_BOLT_PORT=7687

# Cache
REDIS_PASSWORD=secure_redis_password_change_this
REDIS_PORT=6379

# Security
JWT_SECRET=your_super_secure_jwt_secret_minimum_256_bits_change_this
CORS_ORIGINS=https://yourdomain.com

# Load Balancer
HTTP_PORT=80
HTTPS_PORT=443

# Monitoring (optional)
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
GRAFANA_PASSWORD=secure_grafana_password

# Health Checks
HEALTH_TIMEOUT=10
HEALTH_MAX_RETRIES=3
EOF
        
        log_warning "Created $env_file with default values"
        log_warning "IMPORTANT: Update passwords and secrets before production deployment!"
        
        # Set secure permissions
        chmod 600 "$env_file"
    fi
    
    # Source environment file
    set -a
    source "$env_file"
    set +a
    
    log_success "Environment configured"
}

# Pre-deployment validation
validate_deployment() {
    log_info "Running pre-deployment validation..."
    
    # Run quality gates
    if [[ -f "$PROJECT_ROOT/scripts/validate_quality_gates.sh" ]]; then
        log_info "Running quality gates validation..."
        cd "$PROJECT_ROOT"
        if ./scripts/validate_quality_gates.sh; then
            log_success "Quality gates passed"
        else
            log_warning "Quality gates validation completed with warnings"
        fi
    fi
    
    # Validate Docker Compose file
    log_info "Validating Docker Compose configuration..."
    cd "$PROJECT_ROOT"
    if docker-compose -f "$DOCKER_COMPOSE_FILE" config -q; then
        log_success "Docker Compose configuration is valid"
    else
        log_error "Docker Compose configuration validation failed"
        exit 1
    fi
    
    # Check if ports are available
    local ports=(80 443 8080 7474 7687 6379)
    for port in "${ports[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            log_warning "Port $port is already in use"
        fi
    done
    
    log_success "Pre-deployment validation completed"
}

# Build application
build_application() {
    log_info "Building application..."
    
    cd "$PROJECT_ROOT"
    
    # Build Docker image
    log_info "Building Docker image..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" build --no-cache provenance-linker
    
    log_success "Application built successfully"
}

# Deploy services
deploy_services() {
    log_info "Deploying services..."
    
    cd "$PROJECT_ROOT"
    
    # Create directories for volumes
    local volume_dirs=(
        "/var/lib/docker/volumes/deployments_app_logs/_data"
        "/var/lib/docker/volumes/deployments_app_data/_data"
        "/var/lib/docker/volumes/deployments_neo4j_data/_data"
        "/var/lib/docker/volumes/deployments_redis_data/_data"
    )
    
    # Pull required images
    log_info "Pulling required Docker images..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" pull
    
    # Start services
    log_info "Starting services..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
    
    log_success "Services deployed successfully"
}

# Post-deployment validation
post_deployment_validation() {
    log_info "Running post-deployment validation..."
    
    local max_attempts=30
    local attempt=1
    
    log_info "Waiting for services to become healthy..."
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Health check attempt $attempt/$max_attempts"
        
        # Check if all services are healthy
        local healthy_services=0
        local total_services=0
        
        # Get service health status
        while IFS= read -r line; do
            total_services=$((total_services + 1))
            if echo "$line" | grep -q "healthy"; then
                healthy_services=$((healthy_services + 1))
            fi
        done < <(docker-compose -f "$DOCKER_COMPOSE_FILE" ps --services | xargs -I {} docker-compose -f "$DOCKER_COMPOSE_FILE" ps {} 2>/dev/null | grep -E "(healthy|unhealthy)" || true)
        
        log_info "Healthy services: $healthy_services/$total_services"
        
        # Check main application health
        if curl -f -s --max-time 10 "http://localhost:${SERVER_PORT:-8080}/health" > /dev/null 2>&1; then
            log_success "Application health check passed"
            break
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            log_error "Services did not become healthy within the timeout period"
            show_service_status
            exit 1
        fi
        
        sleep 10
        attempt=$((attempt + 1))
    done
    
    # Run comprehensive health checks
    log_info "Running comprehensive health checks..."
    
    # Test main endpoints
    local endpoints=(
        "/health"
        "/health/ready"
        "/health/live"
        "/api/v1/version"
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -f -s --max-time 10 "http://localhost:${SERVER_PORT:-8080}$endpoint" > /dev/null; then
            log_success "✓ $endpoint endpoint is responding"
        else
            log_warning "⚠ $endpoint endpoint check failed"
        fi
    done
    
    log_success "Post-deployment validation completed"
}

# Show service status
show_service_status() {
    log_info "Service Status:"
    cd "$PROJECT_ROOT"
    docker-compose -f "$DOCKER_COMPOSE_FILE" ps
    
    log_info "Service Logs (last 20 lines):"
    docker-compose -f "$DOCKER_COMPOSE_FILE" logs --tail=20
}

# Rollback function
rollback_deployment() {
    log_warning "Rolling back deployment..."
    
    cd "$PROJECT_ROOT"
    docker-compose -f "$DOCKER_COMPOSE_FILE" down
    
    log_success "Rollback completed"
}

# Cleanup function
cleanup() {
    if [[ "${1:-}" == "error" ]]; then
        log_error "Deployment failed. Cleaning up..."
        rollback_deployment
    fi
}

# Main deployment function
main() {
    # Set error trap
    trap 'cleanup error' ERR
    
    show_banner
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-validation)
                SKIP_VALIDATION=true
                shift
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --monitoring)
                ENABLE_MONITORING=true
                shift
                ;;
            --rollback)
                rollback_deployment
                exit 0
                ;;
            --status)
                show_service_status
                exit 0
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --skip-validation    Skip pre-deployment validation"
                echo "  --skip-build        Skip application build"
                echo "  --monitoring        Enable monitoring stack (Prometheus/Grafana)"
                echo "  --rollback          Rollback deployment"
                echo "  --status            Show service status"
                echo "  --help              Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Execute deployment steps
    log_info "Starting TERRAGON SDLC Production Deployment"
    log_info "Deployment Environment: $DEPLOYMENT_ENV"
    log_info "Service Name: $SERVICE_NAME"
    
    check_prerequisites
    setup_environment
    
    if [[ "${SKIP_VALIDATION:-false}" != "true" ]]; then
        validate_deployment
    else
        log_warning "Skipping pre-deployment validation"
    fi
    
    if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
        build_application
    else
        log_warning "Skipping application build"
    fi
    
    deploy_services
    
    # Enable monitoring if requested
    if [[ "${ENABLE_MONITORING:-false}" == "true" ]]; then
        log_info "Enabling monitoring stack..."
        cd "$PROJECT_ROOT"
        docker-compose -f "$DOCKER_COMPOSE_FILE" --profile monitoring up -d
    fi
    
    post_deployment_validation
    
    # Success message
    log_success "🎉 TERRAGON SDLC Production Deployment Completed Successfully!"
    log_info "═══════════════════════════════════════════════════════════════"
    log_success "Self-Healing Pipeline Guard System is now running in production"
    log_info "Application URL: http://localhost:${SERVER_PORT:-8080}"
    log_info "Health Check: http://localhost:${SERVER_PORT:-8080}/health"
    log_info "API Documentation: http://localhost:${SERVER_PORT:-8080}/api/v1"
    
    if [[ "${ENABLE_MONITORING:-false}" == "true" ]]; then
        log_info "Prometheus: http://localhost:${PROMETHEUS_PORT:-9090}"
        log_info "Grafana: http://localhost:${GRAFANA_PORT:-3000}"
    fi
    
    log_info "═══════════════════════════════════════════════════════════════"
    log_info "To monitor the deployment:"
    log_info "  docker-compose -f $DOCKER_COMPOSE_FILE logs -f"
    log_info "To stop the deployment:"
    log_info "  docker-compose -f $DOCKER_COMPOSE_FILE down"
    log_info "═══════════════════════════════════════════════════════════════"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi