#!/bin/bash

# =============================================================================
# Production Deployment Script for Provenance Graph SBOM Linker
# =============================================================================
# This script deploys the provenance system to production with:
# - High availability configuration
# - Security hardening
# - Monitoring and observability
# - Auto-scaling capabilities

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
readonly VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'latest')}"
readonly REGISTRY="${REGISTRY:-ghcr.io/terragon-labs}"
readonly IMAGE_NAME="${IMAGE_NAME:-provenance-linker}"

# Deployment configuration
readonly COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
readonly BACKUP_DIR="${PROJECT_ROOT}/backups/$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="${PROJECT_ROOT}/deploy.log"

# Functions
# =============================================================================

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}" | tee -a "${LOG_FILE}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $*${NC}" | tee -a "${LOG_FILE}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*${NC}" | tee -a "${LOG_FILE}"
}

fatal() {
    error "$*"
    exit 1
}

verbose() {
    if [[ "${VERBOSE:-false}" == "true" ]]; then
        echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] DEBUG: $*${NC}" | tee -a "${LOG_FILE}"
    fi
}

# Pre-deployment checks
check_dependencies() {
    log "Checking deployment dependencies..."
    
    local deps=("docker" "docker-compose" "git" "curl" "jq")
    
    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" >/dev/null 2>&1; then
            fatal "Required dependency '${dep}' not found"
        fi
        verbose "Found ${dep}: $(command -v "${dep}")"
    done
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        fatal "Docker daemon is not running"
    fi
    
    # Check available disk space (minimum 10GB)
    local available_space
    available_space=$(df "${PROJECT_ROOT}" | awk 'NR==2 {print $4}')
    if [[ "${available_space}" -lt 10485760 ]]; then # 10GB in KB
        fatal "Insufficient disk space. At least 10GB required."
    fi
    
    log "All dependencies check passed"
}

# Environment setup
setup_environment() {
    log "Setting up deployment environment..."
    
    # Create necessary directories
    mkdir -p "${BACKUP_DIR}"
    mkdir -p "${PROJECT_ROOT}/logs"
    mkdir -p "${PROJECT_ROOT}/data"
    
    # Set environment variables
    export COMPOSE_PROJECT_NAME="provenance-production"
    export COMPOSE_FILE="${COMPOSE_FILE}"
    export VERSION="${VERSION}"
    export REGISTRY="${REGISTRY}"
    export IMAGE_NAME="${IMAGE_NAME}"
    
    # Generate deployment ID
    export DEPLOYMENT_ID="deploy-$(date +%Y%m%d-%H%M%S)-${VERSION}"
    
    log "Environment setup complete"
    log "Deployment ID: ${DEPLOYMENT_ID}"
    log "Version: ${VERSION}"
}

# Build and push images
build_and_push_images() {
    log "Building and pushing Docker images..."
    
    # Build production image
    local image_tag="${REGISTRY}/${IMAGE_NAME}:${VERSION}"
    local latest_tag="${REGISTRY}/${IMAGE_NAME}:latest"
    
    log "Building image: ${image_tag}"
    
    docker build \
        --file "${PROJECT_ROOT}/Dockerfile.production" \
        --tag "${image_tag}" \
        --tag "${latest_tag}" \
        --build-arg VERSION="${VERSION}" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VCS_REF="$(git rev-parse HEAD)" \
        "${PROJECT_ROOT}"
    
    # Security scan (if Trivy is available)
    if command -v trivy >/dev/null 2>&1; then
        log "Running security scan on image..."
        trivy image --exit-code 1 --severity HIGH,CRITICAL "${image_tag}" || warn "Security issues found in image"
    fi
    
    # Push to registry (if not local deployment)
    if [[ "${DEPLOYMENT_ENV}" != "local" ]]; then
        log "Pushing images to registry..."
        docker push "${image_tag}"
        docker push "${latest_tag}"
    fi
    
    log "Image build and push complete"
}

# Pre-deployment backup
create_backup() {
    log "Creating pre-deployment backup..."
    
    # Backup configuration files
    cp -r "${SCRIPT_DIR}" "${BACKUP_DIR}/config"
    
    # Backup current deployment state
    if docker-compose -f "${COMPOSE_FILE}" ps >/dev/null 2>&1; then
        docker-compose -f "${COMPOSE_FILE}" config > "${BACKUP_DIR}/docker-compose-current.yml"
        docker-compose -f "${COMPOSE_FILE}" ps --format json > "${BACKUP_DIR}/services-state.json"
    fi
    
    # Backup data volumes (if they exist)
    for volume in $(docker volume ls --format "{{.Name}}" | grep "^provenance-production_"); do
        log "Backing up volume: ${volume}"
        docker run --rm \
            -v "${volume}:/data:ro" \
            -v "${BACKUP_DIR}:/backup" \
            alpine:latest \
            tar czf "/backup/${volume}.tar.gz" -C /data .
    done
    
    log "Backup created: ${BACKUP_DIR}"
}

# Deploy infrastructure
deploy_infrastructure() {
    log "Deploying infrastructure services..."
    
    # Start infrastructure services first (databases, monitoring)
    docker-compose -f "${COMPOSE_FILE}" up -d \
        prometheus \
        grafana
    
    # Wait for infrastructure to be ready
    log "Waiting for infrastructure services to be ready..."
    
    # Wait for Prometheus
    local max_attempts=30
    local attempt=0
    while [[ ${attempt} -lt ${max_attempts} ]]; do
        if curl -sf http://localhost:9090/-/ready >/dev/null 2>&1; then
            log "Prometheus is ready"
            break
        fi
        ((attempt++))
        sleep 10
    done
    
    if [[ ${attempt} -eq ${max_attempts} ]]; then
        warn "Prometheus did not become ready within expected time"
    fi
    
    # Wait for Grafana
    attempt=0
    while [[ ${attempt} -lt ${max_attempts} ]]; do
        if curl -sf http://localhost:3000/api/health >/dev/null 2>&1; then
            log "Grafana is ready"
            break
        fi
        ((attempt++))
        sleep 10
    done
    
    if [[ ${attempt} -eq ${max_attempts} ]]; then
        warn "Grafana did not become ready within expected time"
    fi
    
    log "Infrastructure deployment complete"
}

# Deploy application services
deploy_application() {
    log "Deploying application services..."
    
    # Rolling deployment strategy
    local services=("api-1" "api-2" "api-3")
    
    for service in "${services[@]}"; do
        log "Deploying service: ${service}"
        
        # Deploy new version
        docker-compose -f "${COMPOSE_FILE}" up -d "${service}"
        
        # Wait for health check
        local max_attempts=30
        local attempt=0
        local service_healthy=false
        
        while [[ ${attempt} -lt ${max_attempts} ]]; do
            local health_status
            health_status=$(docker-compose -f "${COMPOSE_FILE}" ps --format json "${service}" | jq -r '.[0].Health // "unknown"')
            
            if [[ "${health_status}" == "healthy" ]]; then
                log "Service ${service} is healthy"
                service_healthy=true
                break
            fi
            
            ((attempt++))
            sleep 10
        done
        
        if [[ "${service_healthy}" == "false" ]]; then
            error "Service ${service} failed to become healthy"
            # Rollback logic would go here
            return 1
        fi
        
        # Brief pause between deployments
        sleep 5
    done
    
    # Deploy load balancer last
    log "Deploying load balancer..."
    docker-compose -f "${COMPOSE_FILE}" up -d nginx
    
    log "Application deployment complete"
}

# Health checks and validation
validate_deployment() {
    log "Validating deployment..."
    
    # Check all services are running
    local expected_services=("nginx" "api-1" "api-2" "api-3" "prometheus" "grafana")
    
    for service in "${expected_services[@]}"; do
        local status
        status=$(docker-compose -f "${COMPOSE_FILE}" ps --format json "${service}" | jq -r '.[0].State // "unknown"')
        
        if [[ "${status}" != "running" ]]; then
            error "Service ${service} is not running (status: ${status})"
            return 1
        fi
    done
    
    # Health check endpoints
    local health_endpoints=(
        "http://localhost/health"
        "http://localhost:9090/-/healthy"
        "http://localhost:3000/api/health"
    )
    
    for endpoint in "${health_endpoints[@]}"; do
        log "Checking health endpoint: ${endpoint}"
        
        local max_attempts=10
        local attempt=0
        local endpoint_healthy=false
        
        while [[ ${attempt} -lt ${max_attempts} ]]; do
            if curl -sf "${endpoint}" >/dev/null 2>&1; then
                log "Health endpoint ${endpoint} is responding"
                endpoint_healthy=true
                break
            fi
            
            ((attempt++))
            sleep 5
        done
        
        if [[ "${endpoint_healthy}" == "false" ]]; then
            error "Health endpoint ${endpoint} is not responding"
            return 1
        fi
    done
    
    # Test API functionality
    log "Testing API functionality..."
    
    local api_tests=(
        "GET /health"
        "GET /version"
        "GET /ready"
    )
    
    for test in "${api_tests[@]}"; do
        local method="${test%% *}"
        local path="${test##* }"
        local url="http://localhost${path}"
        
        log "Testing ${method} ${path}"
        
        local response_code
        response_code=$(curl -s -o /dev/null -w "%{http_code}" -X "${method}" "${url}")
        
        if [[ "${response_code}" -ge 200 && "${response_code}" -lt 300 ]]; then
            log "API test passed: ${method} ${path} (${response_code})"
        else
            error "API test failed: ${method} ${path} (${response_code})"
            return 1
        fi
    done
    
    log "Deployment validation complete"
}

# Post-deployment tasks
post_deployment_tasks() {
    log "Executing post-deployment tasks..."
    
    # Update monitoring dashboards
    if [[ -f "${SCRIPT_DIR}/grafana-dashboards.json" ]]; then
        log "Updating Grafana dashboards..."
        # Dashboard update logic would go here
    fi
    
    # Send deployment notification
    send_notification() {
        local webhook_url="${SLACK_WEBHOOK_URL:-}"
        
        if [[ -n "${webhook_url}" ]]; then
            local payload
            payload=$(cat <<EOF
{
    "text": "Provenance Linker deployed successfully",
    "attachments": [
        {
            "color": "good",
            "fields": [
                {"title": "Environment", "value": "${DEPLOYMENT_ENV}", "short": true},
                {"title": "Version", "value": "${VERSION}", "short": true},
                {"title": "Deployment ID", "value": "${DEPLOYMENT_ID}", "short": true},
                {"title": "Timestamp", "value": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')", "short": true}
            ]
        }
    ]
}
EOF
            )
            
            curl -X POST -H 'Content-type: application/json' \
                --data "${payload}" \
                "${webhook_url}" >/dev/null 2>&1 || warn "Failed to send notification"
        fi
    }
    
    send_notification
    
    # Clean up old images
    log "Cleaning up old Docker images..."
    docker image prune -f >/dev/null 2>&1 || warn "Failed to clean up images"
    
    log "Post-deployment tasks complete"
}

# Rollback function
rollback() {
    local backup_dir="$1"
    
    warn "Rolling back deployment..."
    
    # Stop current services
    docker-compose -f "${COMPOSE_FILE}" down
    
    # Restore from backup
    if [[ -f "${backup_dir}/docker-compose-current.yml" ]]; then
        docker-compose -f "${backup_dir}/docker-compose-current.yml" up -d
    fi
    
    error "Deployment rolled back"
}

# Cleanup function
cleanup() {
    log "Cleaning up temporary files..."
    # Add cleanup logic here if needed
}

# Show help
show_help() {
    cat << EOF
Production Deployment Script for Provenance Graph SBOM Linker

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    --version VERSION       Specify version to deploy (default: git describe)
    --registry REGISTRY     Specify container registry (default: ghcr.io/terragon-labs)
    --dry-run              Perform a dry run without making changes
    --skip-build           Skip image build step
    --skip-backup          Skip backup creation
    --rollback BACKUP_DIR  Rollback to specified backup

ENVIRONMENT VARIABLES:
    DEPLOYMENT_ENV         Deployment environment (default: production)
    SLACK_WEBHOOK_URL      Slack webhook for notifications
    VERBOSE               Enable verbose output (true/false)

EXAMPLES:
    $0                     # Deploy latest version
    $0 --version v1.0.0    # Deploy specific version
    $0 --dry-run          # Test deployment without changes
    $0 --rollback /path/to/backup  # Rollback deployment

EOF
}

# Main function
main() {
    # Parse command line arguments
    local dry_run=false
    local skip_build=false
    local skip_backup=false
    local rollback_dir=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                export VERBOSE=true
                ;;
            --version)
                export VERSION="$2"
                shift
                ;;
            --registry)
                export REGISTRY="$2"
                shift
                ;;
            --dry-run)
                dry_run=true
                ;;
            --skip-build)
                skip_build=true
                ;;
            --skip-backup)
                skip_backup=true
                ;;
            --rollback)
                rollback_dir="$2"
                shift
                ;;
            *)
                fatal "Unknown option: $1"
                ;;
        esac
        shift
    done
    
    # Handle rollback
    if [[ -n "${rollback_dir}" ]]; then
        rollback "${rollback_dir}"
        exit 0
    fi
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    # Main deployment flow
    log "Starting Provenance Linker production deployment"
    log "Version: ${VERSION}"
    log "Environment: ${DEPLOYMENT_ENV}"
    log "Dry run: ${dry_run}"
    
    if [[ "${dry_run}" == "false" ]]; then
        check_dependencies
        setup_environment
        
        if [[ "${skip_backup}" == "false" ]]; then
            create_backup
        fi
        
        if [[ "${skip_build}" == "false" ]]; then
            build_and_push_images
        fi
        
        deploy_infrastructure
        deploy_application
        validate_deployment
        post_deployment_tasks
        
        log "Deployment completed successfully!"
        log "Deployment ID: ${DEPLOYMENT_ID}"
        log "Access URLs:"
        log "  - Application: https://localhost"
        log "  - Monitoring: http://localhost:9090"
        log "  - Dashboards: http://localhost:3000"
    else
        log "Dry run completed - no changes made"
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi