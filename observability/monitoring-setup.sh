#!/bin/bash

# Monitoring Setup Script for Provenance Graph SBOM Linker
# =============================================================================
# Deploys and configures comprehensive monitoring infrastructure

set -e

# Configuration
NAMESPACE="${NAMESPACE:-monitoring}"
ENVIRONMENT="${ENVIRONMENT:-development}"
DOMAIN="${DOMAIN:-monitoring.local}"
STORAGE_CLASS="${STORAGE_CLASS:-standard}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy monitoring infrastructure for Provenance Graph SBOM Linker

OPTIONS:
    -h, --help              Show this help message
    -n, --namespace NAME    Kubernetes namespace (default: monitoring)
    -e, --environment ENV   Environment (development|staging|production)
    -d, --domain DOMAIN     Base domain for services (default: monitoring.local)
    -s, --storage-class     Storage class for persistent volumes
    -r, --retention DAYS    Metrics retention period in days (default: 30)
    --dry-run              Show what would be deployed without executing
    --cleanup              Remove monitoring infrastructure

EXAMPLES:
    $0 --environment production --domain monitor.company.com
    $0 --cleanup --namespace monitoring
    $0 --dry-run --environment staging

EOF
}

# Parse command line arguments
DRY_RUN=false
CLEANUP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -s|--storage-class)
            STORAGE_CLASS="$2"
            shift 2
            ;;
        -r|--retention)
            RETENTION_DAYS="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Cleanup function
cleanup_monitoring() {
    print_section "Cleaning up monitoring infrastructure"
    
    # Remove Helm releases
    helm uninstall prometheus-stack -n "${NAMESPACE}" --ignore-not-found
    helm uninstall grafana -n "${NAMESPACE}" --ignore-not-found
    helm uninstall jaeger -n "${NAMESPACE}" --ignore-not-found
    helm uninstall alertmanager -n "${NAMESPACE}" --ignore-not-found
    
    # Remove custom resources
    kubectl delete -f observability/ --ignore-not-found=true
    
    # Remove namespace
    kubectl delete namespace "${NAMESPACE}" --ignore-not-found=true
    
    print_success "Monitoring infrastructure cleaned up"
    exit 0
}

# Check prerequisites
check_prerequisites() {
    print_section "Checking prerequisites"
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is required but not installed"
        exit 1
    fi
    
    # Check helm
    if ! command -v helm &> /dev/null; then
        print_error "helm is required but not installed"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Create namespace
create_namespace() {
    print_info "Creating namespace: ${NAMESPACE}"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        print_info "[DRY RUN] Would create namespace ${NAMESPACE}"
        return
    fi
    
    kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
    
    # Label namespace
    kubectl label namespace "${NAMESPACE}" \
        name="${NAMESPACE}" \
        environment="${ENVIRONMENT}" \
        component=monitoring \
        --overwrite
    
    print_success "Namespace ${NAMESPACE} created"
}

# Add Helm repositories
add_helm_repos() {
    print_section "Adding Helm repositories"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        print_info "[DRY RUN] Would add Helm repositories"
        return
    fi
    
    # Add Prometheus community repo
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    
    # Add Grafana repo
    helm repo add grafana https://grafana.github.io/helm-charts
    
    # Add Jaeger repo
    helm repo add jaegertracing https://jaegertracing.github.io/helm-charts
    
    # Update repos
    helm repo update
    
    print_success "Helm repositories added and updated"
}

# Deploy Prometheus stack
deploy_prometheus() {
    print_section "Deploying Prometheus stack"
    
    local values_file="/tmp/prometheus-values.yaml"
    
    cat << EOF > "${values_file}"
prometheus:
  prometheusSpec:
    retention: ${RETENTION_DAYS}d
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: ${STORAGE_CLASS}
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 50Gi
    additionalScrapeConfigs: |
      - job_name: 'provenance-linker'
        static_configs:
          - targets: ['provenance-linker:8080']
        scrape_interval: 15s
        metrics_path: /metrics
      - job_name: 'neo4j'
        static_configs:
          - targets: ['neo4j:7474']
        scrape_interval: 30s
        metrics_path: /metrics
      - job_name: 'redis'
        static_configs:
          - targets: ['redis:6379']
        scrape_interval: 30s

grafana:
  adminPassword: ${GRAFANA_PASSWORD:-admin123}
  ingress:
    enabled: true
    hosts:
      - grafana.${DOMAIN}
  persistence:
    enabled: true
    storageClassName: ${STORAGE_CLASS}
    size: 10Gi

alertmanager:
  alertmanagerSpec:
    storage:
      volumeClaimTemplate:
        spec:
          storageClassName: ${STORAGE_CLASS}
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 5Gi

nodeExporter:
  enabled: true

kubeStateMetrics:
  enabled: true

defaultRules:
  create: true
  rules:
    etcd: false
    kubeScheduler: false
EOF

    if [[ "${DRY_RUN}" == "true" ]]; then
        print_info "[DRY RUN] Would deploy Prometheus stack with values:"
        cat "${values_file}"
        return
    fi
    
    helm upgrade --install prometheus-stack prometheus-community/kube-prometheus-stack \
        --namespace "${NAMESPACE}" \
        --values "${values_file}" \
        --wait \
        --timeout 10m
    
    print_success "Prometheus stack deployed"
}

# Deploy Jaeger
deploy_jaeger() {
    print_section "Deploying Jaeger tracing"
    
    local values_file="/tmp/jaeger-values.yaml"
    
    cat << EOF > "${values_file}"
strategy: production

collector:
  resources:
    limits:
      cpu: 1
      memory: 1Gi
    requests:
      cpu: 500m
      memory: 512Mi

query:
  ingress:
    enabled: true
    hosts:
      - jaeger.${DOMAIN}
  resources:
    limits:
      cpu: 500m
      memory: 512Mi

agent:
  resources:
    limits:
      cpu: 200m
      memory: 256Mi

storage:
  type: elasticsearch
  options:
    es:
      server-urls: http://elasticsearch:9200
      username: elastic
      password: ${ELASTICSEARCH_PASSWORD:-elastic123}

provisionDataStore:
  cassandra: false
  elasticsearch: true
EOF

    if [[ "${DRY_RUN}" == "true" ]]; then
        print_info "[DRY RUN] Would deploy Jaeger with values:"
        cat "${values_file}"
        return
    fi
    
    helm upgrade --install jaeger jaegertracing/jaeger \
        --namespace "${NAMESPACE}" \
        --values "${values_file}" \
        --wait \
        --timeout 10m
    
    print_success "Jaeger deployed"
}

# Deploy custom monitoring resources
deploy_custom_resources() {
    print_section "Deploying custom monitoring resources"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        print_info "[DRY RUN] Would deploy custom monitoring resources"
        return
    fi
    
    # Apply Prometheus rules
    kubectl apply -f observability/prometheus-rules.yaml -n "${NAMESPACE}"
    
    # Apply SLO configuration
    kubectl create configmap slo-config \
        --from-file=observability/slo-config.yaml \
        -n "${NAMESPACE}" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply OpenTelemetry configuration
    kubectl create configmap otel-config \
        --from-file=observability/otel-config.yaml \
        -n "${NAMESPACE}" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    print_success "Custom monitoring resources deployed"
}

# Deploy Grafana dashboards
deploy_dashboards() {
    print_section "Deploying Grafana dashboards"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        print_info "[DRY RUN] Would deploy Grafana dashboards"
        return
    fi
    
    # Wait for Grafana to be ready
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=grafana -n "${NAMESPACE}" --timeout=300s
    
    # Import dashboard
    kubectl create configmap grafana-dashboard-provenance \
        --from-file=observability/grafana-dashboard.json \
        -n "${NAMESPACE}" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Label for auto-import
    kubectl label configmap grafana-dashboard-provenance \
        grafana_dashboard=1 \
        -n "${NAMESPACE}"
    
    print_success "Grafana dashboards deployed"
}

# Setup alerting
setup_alerting() {
    print_section "Setting up alerting"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        print_info "[DRY RUN] Would setup alerting configuration"
        return
    fi
    
    # Create alerting configuration
    local alertmanager_config="/tmp/alertmanager-config.yaml"
    
    cat << EOF > "${alertmanager_config}"
global:
  smtp_smarthost: '${SMTP_HOST:-localhost:587}'
  smtp_from: 'alerts@${DOMAIN}'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'
  routes:
  - match:
      severity: critical
    receiver: 'critical-alerts'
  - match:
      severity: warning
    receiver: 'warning-alerts'

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: '${WEBHOOK_URL:-http://alertmanager-webhook:5001/webhook}'

- name: 'critical-alerts'
  slack_configs:
  - api_url: '${SLACK_WEBHOOK_CRITICAL:-}'
    channel: '#alerts-critical'
    title: 'Critical Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

- name: 'warning-alerts'
  slack_configs:
  - api_url: '${SLACK_WEBHOOK_WARNINGS:-}'
    channel: '#alerts-warnings'
    title: 'Warning Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'dev', 'instance']
EOF

    kubectl create secret generic alertmanager-config \
        --from-file=alertmanager.yml="${alertmanager_config}" \
        -n "${NAMESPACE}" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    print_success "Alerting configuration deployed"
}

# Verify deployment
verify_deployment() {
    print_section "Verifying deployment"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        print_info "[DRY RUN] Would verify deployment"
        return
    fi
    
    # Check pod status
    print_info "Checking pod status..."
    kubectl get pods -n "${NAMESPACE}"
    
    # Check services
    print_info "Checking services..."
    kubectl get svc -n "${NAMESPACE}"
    
    # Check ingresses
    print_info "Checking ingresses..."
    kubectl get ingress -n "${NAMESPACE}"
    
    # Test Prometheus
    print_info "Testing Prometheus connectivity..."
    kubectl port-forward svc/prometheus-stack-kube-prom-prometheus 9090:9090 -n "${NAMESPACE}" &
    PROMETHEUS_PID=$!
    sleep 5
    
    if curl -s http://localhost:9090/-/healthy > /dev/null; then
        print_success "Prometheus is healthy"
    else
        print_warning "Prometheus health check failed"
    fi
    
    kill $PROMETHEUS_PID 2>/dev/null || true
    
    print_success "Deployment verification completed"
}

# Print access information
print_access_info() {
    print_section "Access Information"
    
    cat << EOF
Monitoring services are now available:

Prometheus:
  URL: http://prometheus.${DOMAIN}
  Port-forward: kubectl port-forward svc/prometheus-stack-kube-prom-prometheus 9090:9090 -n ${NAMESPACE}

Grafana:
  URL: http://grafana.${DOMAIN}
  Username: admin
  Password: ${GRAFANA_PASSWORD:-admin123}
  Port-forward: kubectl port-forward svc/prometheus-stack-grafana 3000:80 -n ${NAMESPACE}

Jaeger:
  URL: http://jaeger.${DOMAIN}
  Port-forward: kubectl port-forward svc/jaeger-query 16686:16686 -n ${NAMESPACE}

AlertManager:
  URL: http://alertmanager.${DOMAIN}
  Port-forward: kubectl port-forward svc/prometheus-stack-kube-prom-alertmanager 9093:9093 -n ${NAMESPACE}

To access services via port-forwarding, run:
  kubectl port-forward -n ${NAMESPACE} svc/<service-name> <local-port>:<service-port>

EOF
}

# Main function
main() {
    print_section "Provenance Graph SBOM Linker - Monitoring Setup"
    
    # Handle cleanup
    if [[ "${CLEANUP}" == "true" ]]; then
        cleanup_monitoring
        exit 0
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Setup monitoring
    create_namespace
    add_helm_repos
    deploy_prometheus
    deploy_jaeger
    deploy_custom_resources
    deploy_dashboards
    setup_alerting
    verify_deployment
    
    # Print access information
    print_access_info
    
    print_success "Monitoring infrastructure deployment completed!"
    print_info "Documentation: observability/alerting-runbooks.md"
}

# Run main function
main "$@"