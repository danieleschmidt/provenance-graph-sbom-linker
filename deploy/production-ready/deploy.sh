#!/bin/bash
# Production Deployment Script for Provenance Graph SBOM Linker
# This script automates the complete production deployment process

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# CONFIGURATION
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEPLOYMENT_ID="$(date +%Y%m%d_%H%M%S)_$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
LOG_FILE="${SCRIPT_DIR}/deployment_${DEPLOYMENT_ID}.log"

# Default values
ENVIRONMENT=${ENVIRONMENT:-production}
DEPLOY_TARGET=${DEPLOY_TARGET:-docker-compose}
SKIP_QUALITY_GATES=${SKIP_QUALITY_GATES:-false}
SKIP_BUILD=${SKIP_BUILD:-false}
SKIP_TESTS=${SKIP_TESTS:-false}
DRY_RUN=${DRY_RUN:-false}
VERSION=${VERSION:-$(git describe --tags --always 2>/dev/null || echo 'dev')}
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT_SHA=$(git rev-parse HEAD 2>/dev/null || echo 'unknown')

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# FUNCTIONS
# =============================================================================
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO)  echo -e "${GREEN}[INFO ]${NC} ${timestamp} - $message" | tee -a "$LOG_FILE" ;;
        WARN)  echo -e "${YELLOW}[WARN ]${NC} ${timestamp} - $message" | tee -a "$LOG_FILE" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" | tee -a "$LOG_FILE" ;;
        DEBUG) echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - $message" | tee -a "$LOG_FILE" ;;
        *) echo "$timestamp - $message" | tee -a "$LOG_FILE" ;;
    esac
}

cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log ERROR "Deployment failed with exit code $exit_code"
        log ERROR "Check log file: $LOG_FILE"
    fi
    exit $exit_code
}

trap cleanup EXIT

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Production deployment script for Provenance Graph SBOM Linker

OPTIONS:
    -e, --environment ENV       Deployment environment (default: production)
    -t, --target TARGET         Deployment target: docker-compose|kubernetes|docker-swarm
    -v, --version VERSION       Version to deploy (default: git describe)
    --skip-quality-gates        Skip quality gate validation
    --skip-build                Skip build phase
    --skip-tests                Skip test execution
    --dry-run                   Show what would be done without executing
    -h, --help                  Show this help message

EXAMPLES:
    $0                                                  # Deploy to production with docker-compose
    $0 -e staging -t kubernetes                        # Deploy to staging with Kubernetes
    $0 --dry-run                                       # Dry run to preview actions
    $0 --skip-quality-gates --skip-tests              # Fast deployment (not recommended)

ENVIRONMENT VARIABLES:
    ENVIRONMENT                 Deployment environment
    DEPLOY_TARGET               Deployment target platform
    SKIP_QUALITY_GATES         Skip quality gates (true/false)
    SKIP_BUILD                 Skip build (true/false)
    SKIP_TESTS                 Skip tests (true/false)
    DRY_RUN                    Dry run mode (true/false)
    VERSION                    Version to deploy

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -t|--target)
                DEPLOY_TARGET="$2"
                shift 2
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            --skip-quality-gates)
                SKIP_QUALITY_GATES=true
                shift
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log ERROR "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

validate_prerequisites() {
    log INFO "Validating deployment prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    command -v docker >/dev/null 2>&1 || missing_tools+=("docker")
    command -v docker-compose >/dev/null 2>&1 || missing_tools+=("docker-compose")
    command -v git >/dev/null 2>&1 || missing_tools+=("git")
    
    if [[ "$DEPLOY_TARGET" == "kubernetes" ]]; then
        command -v kubectl >/dev/null 2>&1 || missing_tools+=("kubectl")
        command -v helm >/dev/null 2>&1 || missing_tools+=("helm")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log ERROR "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log WARN "Not in a git repository. Some features may be limited."
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log ERROR "Docker daemon is not running"
        exit 1
    fi
    
    log INFO "All prerequisites validated successfully"
}

run_quality_gates() {
    if [[ "$SKIP_QUALITY_GATES" == "true" ]]; then
        log WARN "Skipping quality gates validation"
        return 0
    fi
    
    log INFO "Running quality gates validation..."
    
    local quality_gates_script="${PROJECT_ROOT}/scripts/quality-gates-enhanced.sh"
    
    if [[ -f "$quality_gates_script" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log INFO "DRY RUN: Would execute quality gates script"
        else
            bash "$quality_gates_script" || {
                log ERROR "Quality gates validation failed"
                return 1
            }
        fi
    else
        log WARN "Quality gates script not found at $quality_gates_script"
    fi
    
    log INFO "Quality gates validation completed"
}

run_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        log WARN "Skipping test execution"
        return 0
    fi
    
    log INFO "Running test suite..."
    
    cd "$PROJECT_ROOT"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "DRY RUN: Would execute test suite"
    else
        # Run unit tests
        go test -v -race -coverprofile=coverage.out ./... || {
            log ERROR "Unit tests failed"
            return 1
        }
        
        # Run integration tests if they exist
        if [[ -d "test/integration" ]]; then
            go test -v -tags=integration ./test/integration/... || {
                log ERROR "Integration tests failed"
                return 1
            }
        fi
    fi
    
    log INFO "Test suite completed successfully"
}

build_images() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        log WARN "Skipping build phase"
        return 0
    fi
    
    log INFO "Building application images..."
    
    cd "$PROJECT_ROOT"
    
    local image_tag="provenance-linker:${VERSION}"
    local build_args="--build-arg VERSION=${VERSION} --build-arg BUILD_DATE=${BUILD_DATE} --build-arg COMMIT_SHA=${COMMIT_SHA}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "DRY RUN: Would build image with tag $image_tag"
    else
        docker build $build_args -f Dockerfile.prod -t "$image_tag" . || {
            log ERROR "Docker build failed"
            return 1
        }
        
        # Tag for registry if needed
        if [[ -n "${DOCKER_REGISTRY:-}" ]]; then
            docker tag "$image_tag" "${DOCKER_REGISTRY}/${image_tag}"
        fi
    fi
    
    log INFO "Image build completed: $image_tag"
}

prepare_environment() {
    log INFO "Preparing deployment environment: $ENVIRONMENT"
    
    local env_file="${SCRIPT_DIR}/.env.${ENVIRONMENT}"
    local template_file="${SCRIPT_DIR}/.env.production"
    
    if [[ ! -f "$env_file" ]]; then
        if [[ -f "$template_file" ]]; then
            log INFO "Creating environment file from template"
            if [[ "$DRY_RUN" == "true" ]]; then
                log INFO "DRY RUN: Would copy $template_file to $env_file"
            else
                cp "$template_file" "$env_file"
                log WARN "Please configure $env_file with appropriate values for $ENVIRONMENT"
            fi
        else
            log ERROR "Environment template not found: $template_file"
            return 1
        fi
    fi
    
    # Create secrets directory structure
    local secrets_dir="${SCRIPT_DIR}/secrets"
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "DRY RUN: Would create secrets directory structure"
    else
        mkdir -p "$secrets_dir"
        
        # Generate placeholder secrets if they don't exist
        [[ -f "${secrets_dir}/neo4j_password.txt" ]] || echo "change-me-neo4j-password" > "${secrets_dir}/neo4j_password.txt"
        [[ -f "${secrets_dir}/redis_password.txt" ]] || echo "change-me-redis-password" > "${secrets_dir}/redis_password.txt"
        [[ -f "${secrets_dir}/jwt_secret.txt" ]] || openssl rand -base64 32 > "${secrets_dir}/jwt_secret.txt"
        
        # Set proper permissions
        chmod 600 "${secrets_dir}"/*
        
        log WARN "Generated placeholder secrets. Please update them with secure values."
    fi
}

deploy_docker_compose() {
    log INFO "Deploying with Docker Compose..."
    
    cd "$SCRIPT_DIR"
    
    local compose_file="docker-compose.production.yml"
    local env_file=".env.${ENVIRONMENT}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "DRY RUN: Would deploy with: docker-compose -f $compose_file --env-file $env_file up -d"
        return 0
    fi
    
    # Validate compose file
    docker-compose -f "$compose_file" config >/dev/null || {
        log ERROR "Docker Compose configuration validation failed"
        return 1
    }
    
    # Deploy
    docker-compose -f "$compose_file" --env-file "$env_file" up -d || {
        log ERROR "Docker Compose deployment failed"
        return 1
    }
    
    log INFO "Deployment completed. Services are starting..."
    
    # Wait for services to be healthy
    sleep 30
    docker-compose -f "$compose_file" ps
}

deploy_kubernetes() {
    log INFO "Deploying to Kubernetes..."
    
    local k8s_dir="${PROJECT_ROOT}/deploy/kubernetes"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "DRY RUN: Would apply Kubernetes manifests from $k8s_dir"
        return 0
    fi
    
    # Check cluster connectivity
    kubectl cluster-info || {
        log ERROR "Cannot connect to Kubernetes cluster"
        return 1
    }
    
    # Apply manifests
    kubectl apply -f "$k8s_dir/" || {
        log ERROR "Kubernetes deployment failed"
        return 1
    }
    
    # Wait for deployment
    kubectl wait --for=condition=available --timeout=300s deployment/provenance-linker -n provenance-system
    
    log INFO "Kubernetes deployment completed"
}

perform_deployment() {
    log INFO "Starting deployment to $ENVIRONMENT using $DEPLOY_TARGET"
    
    case "$DEPLOY_TARGET" in
        docker-compose)
            deploy_docker_compose
            ;;
        kubernetes)
            deploy_kubernetes
            ;;
        docker-swarm)
            log ERROR "Docker Swarm deployment not yet implemented"
            return 1
            ;;
        *)
            log ERROR "Unknown deployment target: $DEPLOY_TARGET"
            return 1
            ;;
    esac
}

run_health_checks() {
    log INFO "Running post-deployment health checks..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "DRY RUN: Would run health checks"
        return 0
    fi
    
    # Wait a bit for services to stabilize
    sleep 15
    
    # Check service health based on deployment target
    case "$DEPLOY_TARGET" in
        docker-compose)
            local health_url="http://localhost:8080/health"
            ;;
        kubernetes)
            local health_url="http://$(kubectl get svc provenance-linker-service -n provenance-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):8080/health"
            ;;
    esac
    
    local retries=0
    local max_retries=10
    
    while [[ $retries -lt $max_retries ]]; do
        if curl -sf "$health_url" >/dev/null 2>&1; then
            log INFO "Health check passed"
            return 0
        fi
        
        retries=$((retries + 1))
        log WARN "Health check failed (attempt $retries/$max_retries). Retrying in 10 seconds..."
        sleep 10
    done
    
    log ERROR "Health checks failed after $max_retries attempts"
    return 1
}

generate_deployment_report() {
    log INFO "Generating deployment report..."
    
    local report_file="${SCRIPT_DIR}/deployment-report-${DEPLOYMENT_ID}.md"
    
    cat > "$report_file" << EOF
# Deployment Report

## Summary
- **Deployment ID**: ${DEPLOYMENT_ID}
- **Environment**: ${ENVIRONMENT}
- **Target**: ${DEPLOY_TARGET}
- **Version**: ${VERSION}
- **Timestamp**: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- **Git Commit**: ${COMMIT_SHA}
- **Status**: SUCCESS

## Configuration
- Skip Quality Gates: ${SKIP_QUALITY_GATES}
- Skip Build: ${SKIP_BUILD}
- Skip Tests: ${SKIP_TESTS}
- Dry Run: ${DRY_RUN}

## Artifacts
- Log File: ${LOG_FILE}
- Environment File: .env.${ENVIRONMENT}
- Compose File: docker-compose.production.yml

## Services
EOF

    if [[ "$DEPLOY_TARGET" == "docker-compose" && "$DRY_RUN" == "false" ]]; then
        echo "### Docker Compose Services" >> "$report_file"
        docker-compose -f "${SCRIPT_DIR}/docker-compose.production.yml" ps >> "$report_file" 2>/dev/null || true
    fi
    
    log INFO "Deployment report generated: $report_file"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
main() {
    log INFO "Starting Provenance Graph SBOM Linker deployment"
    log INFO "Deployment ID: $DEPLOYMENT_ID"
    
    parse_arguments "$@"
    
    log INFO "Configuration:"
    log INFO "  Environment: $ENVIRONMENT"
    log INFO "  Target: $DEPLOY_TARGET"
    log INFO "  Version: $VERSION"
    log INFO "  Dry Run: $DRY_RUN"
    
    validate_prerequisites
    run_quality_gates
    run_tests
    build_images
    prepare_environment
    perform_deployment
    run_health_checks
    generate_deployment_report
    
    log INFO "Deployment completed successfully!"
    log INFO "Deployment ID: $DEPLOYMENT_ID"
    log INFO "Log file: $LOG_FILE"
}

# Execute main function with all arguments
main "$@"