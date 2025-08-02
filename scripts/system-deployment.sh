#!/bin/bash

# System Deployment Script for Provenance Graph SBOM Linker
# =============================================================================
# Complete system deployment and integration orchestration

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEPLOY_DIR="${PROJECT_ROOT}/deploy"
LOG_DIR="${PROJECT_ROOT}/logs/deployment"

# Default values
ENVIRONMENT="production"
NAMESPACE="provenance-system"
RELEASE_NAME="provenance-linker"
DOMAIN="provenance.company.com"
DRY_RUN=false
SKIP_VALIDATION=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Setup logging
mkdir -p "${LOG_DIR}"
LOGFILE="${LOG_DIR}/deployment-$(date +%Y%m%d-%H%M%S).log"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "${LOGFILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "${LOGFILE}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "${LOGFILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOGFILE}"
}

log_section() {
    echo -e "\n${PURPLE}=== $1 ===${NC}\n" | tee -a "${LOGFILE}"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 <command> [options]

Complete system deployment and integration orchestration

COMMANDS:
    deploy              Deploy the complete system
    upgrade             Upgrade existing deployment
    rollback            Rollback to previous version
    destroy             Remove the complete system
    validate            Validate deployment configuration
    status              Check deployment status
    logs                View deployment logs
    scale               Scale the deployment
    backup              Create system backup
    restore             Restore from backup

OPTIONS:
    -h, --help              Show this help message
    -e, --environment ENV   Target environment (dev/staging/prod)
    -n, --namespace NAME    Kubernetes namespace
    -d, --domain DOMAIN     Application domain
    -r, --release NAME      Helm release name
    --dry-run              Show what would be deployed
    --skip-validation      Skip pre-deployment validation
    --wait                 Wait for deployment to complete
    --timeout DURATION     Deployment timeout (default: 10m)
    --values FILE          Additional Helm values file

EXAMPLES:
    $0 deploy --environment production --domain provenance.company.com
    $0 upgrade --wait --timeout 15m
    $0 validate --environment staging
    $0 scale --replicas 5
    $0 rollback --revision 2

EOF
}

# Validate prerequisites
validate_prerequisites() {
    log_section "Validating Prerequisites"
    
    local missing_tools=()
    
    # Check required tools
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi
    
    if ! command -v helm &> /dev/null; then
        missing_tools+=("helm")
    fi
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install the missing tools and try again"
        exit 1
    fi
    
    # Check Kubernetes connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        log_info "Please ensure kubectl is configured correctly"
        exit 1
    fi
    
    # Check Helm repositories
    log_info "Adding required Helm repositories..."
    helm repo add bitnami https://charts.bitnami.com/bitnami &> /dev/null || true
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts &> /dev/null || true
    helm repo add grafana https://grafana.github.io/helm-charts &> /dev/null || true
    helm repo update &> /dev/null
    
    log_success "Prerequisites validation completed"
}

# Validate deployment configuration
validate_deployment_config() {
    log_section "Validating Deployment Configuration"
    
    # Check configuration files exist
    local config_files=(
        "${DEPLOY_DIR}/integration-config.yaml"
        "${PROJECT_ROOT}/observability/otel-config.yaml"
        "${PROJECT_ROOT}/observability/prometheus-rules.yaml"
        "${PROJECT_ROOT}/metrics/metrics-collection.yaml"
    )
    
    for config_file in "${config_files[@]}"; do
        if [[ ! -f "$config_file" ]]; then
            log_error "Configuration file not found: $config_file"
            return 1
        fi
    done
    
    # Validate Kubernetes manifests
    log_info "Validating Kubernetes manifests..."
    if kubectl apply --dry-run=client -f "${DEPLOY_DIR}/integration-config.yaml" &> /dev/null; then
        log_success "Kubernetes manifests are valid"
    else
        log_error "Invalid Kubernetes manifests found"
        return 1
    fi
    
    # Check container image availability
    log_info "Checking container image availability..."
    local image="ghcr.io/danieleschmidt/provenance-graph-sbom-linker:latest"
    if docker manifest inspect "$image" &> /dev/null; then
        log_success "Container image is available: $image"
    else
        log_warning "Container image may not be available: $image"
    fi
    
    log_success "Deployment configuration validation completed"
}

# Create namespace and setup RBAC
setup_namespace() {
    log_section "Setting up Namespace and RBAC"
    
    # Create namespace if it doesn't exist
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "Creating namespace: $NAMESPACE"
        kubectl create namespace "$NAMESPACE"
        kubectl label namespace "$NAMESPACE" \
            app=provenance-graph-sbom-linker \
            environment="$ENVIRONMENT" \
            security=high
    else
        log_info "Namespace already exists: $NAMESPACE"
    fi
    
    # Apply RBAC configuration
    log_info "Setting up RBAC..."
    kubectl apply -f "${DEPLOY_DIR}/integration-config.yaml" -n "$NAMESPACE"
    
    log_success "Namespace and RBAC setup completed"
}

# Deploy infrastructure components
deploy_infrastructure() {
    log_section "Deploying Infrastructure Components"
    
    # Deploy Neo4j database
    log_info "Deploying Neo4j database..."
    helm upgrade --install neo4j bitnami/neo4j \
        --namespace "$NAMESPACE" \
        --set auth.password="secure-neo4j-password" \
        --set persistence.enabled=true \
        --set persistence.size=20Gi \
        --set resources.requests.memory=2Gi \
        --set resources.limits.memory=4Gi \
        --wait --timeout=10m
    
    # Deploy Redis cache
    log_info "Deploying Redis cache..."
    helm upgrade --install redis bitnami/redis \
        --namespace "$NAMESPACE" \
        --set auth.password="secure-redis-password" \
        --set persistence.enabled=true \
        --set persistence.size=5Gi \
        --set resources.requests.memory=512Mi \
        --set resources.limits.memory=1Gi \
        --wait --timeout=5m
    
    # Deploy MinIO object storage
    log_info "Deploying MinIO object storage..."
    helm upgrade --install minio bitnami/minio \
        --namespace "$NAMESPACE" \
        --set auth.rootUser="provenance-access-key" \
        --set auth.rootPassword="secure-minio-secret-key" \
        --set persistence.enabled=true \
        --set persistence.size=50Gi \
        --set resources.requests.memory=1Gi \
        --set resources.limits.memory=2Gi \
        --wait --timeout=10m
    
    log_success "Infrastructure components deployed"
}

# Deploy monitoring stack
deploy_monitoring() {
    log_section "Deploying Monitoring Stack"
    
    # Create monitoring namespace if it doesn't exist
    local monitoring_namespace="monitoring"
    if ! kubectl get namespace "$monitoring_namespace" &> /dev/null; then
        kubectl create namespace "$monitoring_namespace"
    fi
    
    # Deploy Prometheus stack
    log_info "Deploying Prometheus monitoring stack..."
    helm upgrade --install prometheus-stack prometheus-community/kube-prometheus-stack \
        --namespace "$monitoring_namespace" \
        --set prometheus.prometheusSpec.retention=30d \
        --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
        --set grafana.adminPassword="secure-grafana-password" \
        --set grafana.persistence.enabled=true \
        --set grafana.persistence.size=10Gi \
        --set alertmanager.alertmanagerSpec.storage.volumeClaimTemplate.spec.resources.requests.storage=5Gi \
        --wait --timeout=15m
    
    # Apply custom monitoring configurations
    log_info "Applying custom monitoring configurations..."
    kubectl apply -f "${PROJECT_ROOT}/observability/prometheus-rules.yaml" -n "$monitoring_namespace"
    kubectl apply -f "${PROJECT_ROOT}/observability/security-monitoring.yaml" -n "$monitoring_namespace"
    kubectl apply -f "${PROJECT_ROOT}/metrics/metrics-collection.yaml" -n "$monitoring_namespace"
    kubectl apply -f "${PROJECT_ROOT}/metrics/kpi-dashboard.yaml" -n "$monitoring_namespace"
    
    log_success "Monitoring stack deployed"
}

# Deploy main application
deploy_application() {
    log_section "Deploying Main Application"
    
    # Apply secrets and configuration
    log_info "Creating application secrets and configuration..."
    kubectl apply -f "${DEPLOY_DIR}/integration-config.yaml" -n "$NAMESPACE"
    
    # Wait for infrastructure to be ready
    log_info "Waiting for infrastructure components to be ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=neo4j -n "$NAMESPACE" --timeout=300s
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n "$NAMESPACE" --timeout=300s
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=minio -n "$NAMESPACE" --timeout=300s
    
    # Deploy the main application
    log_info "Deploying main application..."
    if [[ "$DRY_RUN" == "true" ]]; then
        kubectl apply --dry-run=client -f "${DEPLOY_DIR}/integration-config.yaml" -n "$NAMESPACE"
        log_info "[DRY RUN] Application deployment completed"
    else
        kubectl apply -f "${DEPLOY_DIR}/integration-config.yaml" -n "$NAMESPACE"
        
        # Wait for deployment to be ready
        kubectl rollout status deployment/provenance-linker -n "$NAMESPACE" --timeout=600s
        
        log_success "Main application deployed successfully"
    fi
}

# Validate deployment
validate_deployment() {
    log_section "Validating Deployment"
    
    # Check pod status
    log_info "Checking pod status..."
    kubectl get pods -n "$NAMESPACE" -l app=provenance-linker
    
    # Check if all pods are ready
    local ready_pods=$(kubectl get pods -n "$NAMESPACE" -l app=provenance-linker --no-headers | grep Running | wc -l)
    local total_pods=$(kubectl get pods -n "$NAMESPACE" -l app=provenance-linker --no-headers | wc -l)
    
    if [[ "$ready_pods" -eq "$total_pods" ]] && [[ "$total_pods" -gt 0 ]]; then
        log_success "All pods are running ($ready_pods/$total_pods)"
    else
        log_error "Not all pods are ready ($ready_pods/$total_pods)"
        return 1
    fi
    
    # Check service endpoints
    log_info "Checking service endpoints..."
    kubectl get endpoints -n "$NAMESPACE"
    
    # Test application health
    log_info "Testing application health..."
    local service_ip=$(kubectl get svc provenance-linker -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    if kubectl run test-curl --rm -i --tty --restart=Never --image=curlimages/curl -- \
        curl -f "http://$service_ip:8080/health" &> /dev/null; then
        log_success "Application health check passed"
    else
        log_warning "Application health check failed or timed out"
    fi
    
    # Check ingress configuration
    if kubectl get ingress provenance-linker -n "$NAMESPACE" &> /dev/null; then
        log_info "Ingress configuration:"
        kubectl get ingress provenance-linker -n "$NAMESPACE" -o wide
    fi
    
    log_success "Deployment validation completed"
}

# Scale deployment
scale_deployment() {
    local replicas="${1:-3}"
    
    log_section "Scaling Deployment"
    
    log_info "Scaling deployment to $replicas replicas..."
    kubectl scale deployment provenance-linker --replicas="$replicas" -n "$NAMESPACE"
    
    # Wait for scaling to complete
    kubectl rollout status deployment/provenance-linker -n "$NAMESPACE" --timeout=300s
    
    log_success "Deployment scaled to $replicas replicas"
}

# Rollback deployment
rollback_deployment() {
    local revision="${1:-}"
    
    log_section "Rolling Back Deployment"
    
    if [[ -n "$revision" ]]; then
        log_info "Rolling back to revision $revision..."
        kubectl rollout undo deployment/provenance-linker --to-revision="$revision" -n "$NAMESPACE"
    else
        log_info "Rolling back to previous revision..."
        kubectl rollout undo deployment/provenance-linker -n "$NAMESPACE"
    fi
    
    # Wait for rollback to complete
    kubectl rollout status deployment/provenance-linker -n "$NAMESPACE" --timeout=300s
    
    log_success "Rollback completed"
}

# Create system backup
create_backup() {
    log_section "Creating System Backup"
    
    local backup_dir="${PROJECT_ROOT}/backups/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup Kubernetes resources
    log_info "Backing up Kubernetes resources..."
    kubectl get all,configmaps,secrets,pvc -n "$NAMESPACE" -o yaml > "$backup_dir/k8s-resources.yaml"
    
    # Backup database (if possible)
    log_info "Creating database backup..."
    kubectl exec -n "$NAMESPACE" deployment/neo4j -- neo4j-admin database dump --to-path=/backups neo4j || true
    
    # Backup configuration files
    log_info "Backing up configuration files..."
    cp -r "$DEPLOY_DIR" "$backup_dir/"
    cp -r "${PROJECT_ROOT}/observability" "$backup_dir/"
    cp -r "${PROJECT_ROOT}/metrics" "$backup_dir/"
    
    log_success "System backup created: $backup_dir"
}

# Destroy deployment
destroy_deployment() {
    log_section "Destroying Deployment"
    
    log_warning "This will completely remove the deployment and all data"
    read -p "Are you sure you want to continue? (y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Deployment destruction cancelled"
        return 0
    fi
    
    # Remove main application
    log_info "Removing main application..."
    kubectl delete -f "${DEPLOY_DIR}/integration-config.yaml" -n "$NAMESPACE" --ignore-not-found=true
    
    # Remove infrastructure components
    log_info "Removing infrastructure components..."
    helm uninstall neo4j -n "$NAMESPACE" --ignore-not-found || true
    helm uninstall redis -n "$NAMESPACE" --ignore-not-found || true
    helm uninstall minio -n "$NAMESPACE" --ignore-not-found || true
    
    # Remove namespace
    log_info "Removing namespace..."
    kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
    
    log_success "Deployment destroyed"
}

# Get deployment status
get_deployment_status() {
    log_section "Deployment Status"
    
    echo "=== Namespace Status ==="
    kubectl get namespace "$NAMESPACE" 2>/dev/null || echo "Namespace not found"
    
    echo -e "\n=== Pod Status ==="
    kubectl get pods -n "$NAMESPACE" -o wide 2>/dev/null || echo "No pods found"
    
    echo -e "\n=== Service Status ==="
    kubectl get services -n "$NAMESPACE" 2>/dev/null || echo "No services found"
    
    echo -e "\n=== Ingress Status ==="
    kubectl get ingress -n "$NAMESPACE" 2>/dev/null || echo "No ingress found"
    
    echo -e "\n=== Storage Status ==="
    kubectl get pvc -n "$NAMESPACE" 2>/dev/null || echo "No PVCs found"
    
    echo -e "\n=== Recent Events ==="
    kubectl get events -n "$NAMESPACE" --sort-by='.metadata.creationTimestamp' | tail -10 2>/dev/null || echo "No events found"
}

# Main execution function
main() {
    local command="$1"
    shift
    
    # Parse options
    local wait=false
    local timeout="10m"
    local values_file=""
    local replicas=3
    local revision=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -r|--release)
                RELEASE_NAME="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --skip-validation)
                SKIP_VALIDATION=true
                shift
                ;;
            --wait)
                wait=true
                shift
                ;;
            --timeout)
                timeout="$2"
                shift 2
                ;;
            --values)
                values_file="$2"
                shift 2
                ;;
            --replicas)
                replicas="$2"
                shift 2
                ;;
            --revision)
                revision="$2"
                shift 2
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    # Validate prerequisites
    validate_prerequisites
    
    # Execute command
    case "$command" in
        deploy)
            log_section "Starting Complete System Deployment"
            [[ "$SKIP_VALIDATION" != "true" ]] && validate_deployment_config
            setup_namespace
            deploy_infrastructure
            deploy_monitoring
            deploy_application
            validate_deployment
            log_success "Complete system deployment finished successfully"
            ;;
        upgrade)
            log_info "Upgrading existing deployment..."
            [[ "$SKIP_VALIDATION" != "true" ]] && validate_deployment_config
            deploy_application
            validate_deployment
            ;;
        rollback)
            rollback_deployment "$revision"
            ;;
        destroy)
            destroy_deployment
            ;;
        validate)
            validate_deployment_config
            validate_deployment
            ;;
        status)
            get_deployment_status
            ;;
        logs)
            kubectl logs -f deployment/provenance-linker -n "$NAMESPACE"
            ;;
        scale)
            scale_deployment "$replicas"
            ;;
        backup)
            create_backup
            ;;
        restore)
            log_error "Restore functionality not yet implemented"
            exit 1
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Trap for cleanup
trap 'log_info "Deployment script interrupted"; exit 1' INT TERM

# Run main function with all arguments
main "$@"