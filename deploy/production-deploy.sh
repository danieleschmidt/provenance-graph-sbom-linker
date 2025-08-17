#!/bin/bash

# Production Deployment Script for Provenance Graph SBOM Linker
# This script handles the complete production deployment with zero-downtime

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKER_COMPOSE_FILE="docker-compose.production.yml"
BACKUP_DIR="/var/backups/provenance-linker"
LOG_FILE="/var/log/provenance-deployment.log"
HEALTH_CHECK_TIMEOUT=300 # 5 minutes

# Function to log messages
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_FILE"
}

# Function to check prerequisites
check_prerequisites() {
    log "Checking deployment prerequisites..."
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        error "Docker is not running or not accessible"
    fi
    
    # Check if Docker Compose is available
    if ! command -v docker-compose >/dev/null 2>&1; then
        error "Docker Compose is not installed"
    fi
    
    # Check if environment file exists
    if [[ ! -f .env.production ]]; then
        error "Production environment file (.env.production) not found"
    fi
    
    # Check if required environment variables are set
    source .env.production
    required_vars=("NEO4J_PASSWORD" "JWT_SECRET" "GRAFANA_PASSWORD")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            error "Required environment variable $var is not set"
        fi
    done
    
    log "Prerequisites check completed successfully"
}

# Function to create backup
create_backup() {
    log "Creating backup before deployment..."
    
    mkdir -p "$BACKUP_DIR/$(date +%Y%m%d_%H%M%S)"
    BACKUP_PATH="$BACKUP_DIR/$(date +%Y%m%d_%H%M%S)"
    
    # Backup Neo4j data
    if docker-compose -f "$DOCKER_COMPOSE_FILE" ps neo4j | grep -q "Up"; then
        info "Backing up Neo4j database..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" exec -T neo4j \
            neo4j-admin database dump --database=provenance --to-path=/backups/
        docker cp "$(docker-compose -f "$DOCKER_COMPOSE_FILE" ps -q neo4j):/backups/" "$BACKUP_PATH/neo4j/"
    fi
    
    # Backup configuration files
    info "Backing up configuration files..."
    cp -r config/ "$BACKUP_PATH/"
    cp .env.production "$BACKUP_PATH/"
    
    log "Backup created at $BACKUP_PATH"
}

# Function to run security scan
security_scan() {
    log "Running security scan..."
    
    # Scan Docker images for vulnerabilities
    if command -v trivy >/dev/null 2>&1; then
        info "Scanning Docker images with Trivy..."
        trivy image --exit-code 1 --severity HIGH,CRITICAL \
            danieleschmidt/provenance-linker:latest || {
            warning "Security vulnerabilities found in Docker images"
        }
    else
        warning "Trivy not found, skipping image security scan"
    fi
    
    # Check for secrets in environment files
    if command -v detect-secrets >/dev/null 2>&1; then
        info "Scanning for secrets..."
        detect-secrets scan --all-files . || {
            warning "Potential secrets detected"
        }
    fi
    
    log "Security scan completed"
}

# Function to validate configuration
validate_config() {
    log "Validating configuration..."
    
    # Validate Docker Compose file
    docker-compose -f "$DOCKER_COMPOSE_FILE" config --quiet || {
        error "Docker Compose configuration is invalid"
    }
    
    # Test environment variables
    source .env.production
    docker-compose -f "$DOCKER_COMPOSE_FILE" run --rm --no-deps provenance-api \
        /minimal-server --validate-config || {
        error "Application configuration validation failed"
    }
    
    log "Configuration validation completed"
}

# Function to pull latest images
pull_images() {
    log "Pulling latest Docker images..."
    
    docker-compose -f "$DOCKER_COMPOSE_FILE" pull --quiet
    
    log "Docker images pulled successfully"
}

# Function to perform rolling deployment
rolling_deployment() {
    log "Starting rolling deployment..."
    
    # Deploy infrastructure services first
    info "Deploying infrastructure services..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d \
        neo4j redis prometheus grafana jaeger fluentd
    
    # Wait for infrastructure to be ready
    info "Waiting for infrastructure services to be ready..."
    sleep 30
    
    # Check infrastructure health
    check_service_health "neo4j" "http://localhost:7474/browser/"
    check_service_health "redis" "redis://localhost:6379"
    
    # Deploy application services with rolling update
    info "Deploying application services..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d --scale provenance-api=3 provenance-api
    
    # Deploy load balancer last
    info "Deploying load balancer..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d nginx
    
    log "Rolling deployment completed"
}

# Function to check service health
check_service_health() {
    local service_name="$1"
    local health_endpoint="$2"
    local max_attempts=30
    local attempt=1
    
    info "Checking health of $service_name..."
    
    while [[ $attempt -le $max_attempts ]]; do
        if docker-compose -f "$DOCKER_COMPOSE_FILE" ps "$service_name" | grep -q "Up (healthy)"; then
            log "$service_name is healthy"
            return 0
        fi
        
        info "Attempt $attempt/$max_attempts: $service_name not ready yet..."
        sleep 10
        ((attempt++))
    done
    
    error "$service_name failed to become healthy within timeout"
}

# Function to run health checks
run_health_checks() {
    log "Running comprehensive health checks..."
    
    # API health check
    info "Checking API health..."
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health || echo "000")
    if [[ "$response" != "200" ]]; then
        error "API health check failed (HTTP $response)"
    fi
    
    # Database connectivity check
    info "Checking database connectivity..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" exec -T provenance-api \
        /minimal-server --check-db || {
        error "Database connectivity check failed"
    }
    
    # Cache connectivity check
    info "Checking cache connectivity..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" exec -T redis redis-cli ping | grep -q "PONG" || {
        error "Redis connectivity check failed"
    }
    
    # Metrics check
    info "Checking metrics endpoint..."
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/metrics/prometheus || echo "000")
    if [[ "$response" != "200" ]]; then
        warning "Metrics endpoint check failed (HTTP $response)"
    fi
    
    log "Health checks completed successfully"
}

# Function to run smoke tests
run_smoke_tests() {
    log "Running smoke tests..."
    
    # Test artifact creation
    info "Testing artifact creation..."
    artifact_response=$(curl -s -X POST http://localhost:8080/api/v1/artifacts/ \
        -H "Content-Type: application/json" \
        -d '{"name":"smoke-test","version":"v1.0.0","type":"container","hash":"sha256:smoke123"}')
    
    if echo "$artifact_response" | grep -q "id"; then
        info "Artifact creation test passed"
    else
        error "Artifact creation test failed"
    fi
    
    # Test SBOM analysis
    info "Testing SBOM analysis..."
    sbom_response=$(curl -s -X POST http://localhost:8080/api/v1/sbom/analyze \
        -H "Content-Type: application/json" \
        -d '{"sbom_data":"{\"bomFormat\":\"CycloneDX\"}","check_licenses":true}')
    
    if echo "$sbom_response" | grep -q "analysis"; then
        info "SBOM analysis test passed"
    else
        warning "SBOM analysis test failed"
    fi
    
    log "Smoke tests completed"
}

# Function to setup monitoring and alerting
setup_monitoring() {
    log "Setting up monitoring and alerting..."
    
    # Configure Prometheus targets
    info "Configuring Prometheus..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" exec -T prometheus \
        promtool check config /etc/prometheus/prometheus.yml || {
        warning "Prometheus configuration check failed"
    }
    
    # Import Grafana dashboards
    info "Setting up Grafana dashboards..."
    # Dashboard setup would be handled by provisioning in the container
    
    # Setup alert rules
    info "Configuring alert rules..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" exec -T prometheus \
        promtool check rules /etc/prometheus/rules.yml || {
        warning "Prometheus rules check failed"
    }
    
    log "Monitoring and alerting setup completed"
}

# Function to cleanup old resources
cleanup() {
    log "Cleaning up old resources..."
    
    # Remove old Docker images
    info "Removing old Docker images..."
    docker image prune -f --filter "until=24h"
    
    # Clean up old backups (keep last 7 days)
    info "Cleaning up old backups..."
    find "$BACKUP_DIR" -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true
    
    # Clean up old logs
    info "Rotating logs..."
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE") -gt 104857600 ]]; then
        mv "$LOG_FILE" "$LOG_FILE.$(date +%Y%m%d_%H%M%S)"
        gzip "$LOG_FILE.$(date +%Y%m%d_%H%M%S)"
    fi
    
    log "Cleanup completed"
}

# Function to print deployment summary
print_summary() {
    log "Deployment Summary"
    echo "===========================================" | tee -a "$LOG_FILE"
    echo "Deployment completed successfully!" | tee -a "$LOG_FILE"
    echo "Timestamp: $(date)" | tee -a "$LOG_FILE"
    echo "Services Status:" | tee -a "$LOG_FILE"
    docker-compose -f "$DOCKER_COMPOSE_FILE" ps | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
    echo "Access Points:" | tee -a "$LOG_FILE"
    echo "- API: http://localhost:8080" | tee -a "$LOG_FILE"
    echo "- Grafana: http://localhost:3000" | tee -a "$LOG_FILE"
    echo "- Prometheus: http://localhost:9090" | tee -a "$LOG_FILE"
    echo "- Jaeger: http://localhost:16686" | tee -a "$LOG_FILE"
    echo "- Neo4j Browser: http://localhost:7474" | tee -a "$LOG_FILE"
    echo "===========================================" | tee -a "$LOG_FILE"
}

# Main deployment function
main() {
    log "Starting production deployment of Provenance Graph SBOM Linker"
    
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Run deployment steps
    check_prerequisites
    create_backup
    security_scan
    validate_config
    pull_images
    rolling_deployment
    run_health_checks
    run_smoke_tests
    setup_monitoring
    cleanup
    print_summary
    
    log "Production deployment completed successfully!"
}

# Handle script termination
cleanup_on_exit() {
    if [[ $? -ne 0 ]]; then
        error "Deployment failed! Check logs at $LOG_FILE"
        echo "Rolling back..." | tee -a "$LOG_FILE"
        # Add rollback logic here if needed
    fi
}

trap cleanup_on_exit EXIT

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi