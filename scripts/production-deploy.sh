#!/bin/bash
# Production Deployment Script for Provenance Graph SBOM Linker
# This script implements Generation 3 deployment with full optimization

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-ghcr.io/danieleschmidt}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
NAMESPACE="${NAMESPACE:-provenance-system}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $*${NC}"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✅ $*${NC}"
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠️  $*${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ❌ $*${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking deployment prerequisites..."
    
    # Check required tools
    local tools=("docker" "kubectl" "helm")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is required but not installed"
            exit 1
        fi
    done
    
    # Check kubectl connection
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Check Helm repositories
    if ! helm repo list | grep -q "bitnami"; then
        log "Adding Bitnami Helm repository..."
        helm repo add bitnami https://charts.bitnami.com/bitnami
    fi
    
    helm repo update
    success "Prerequisites check completed"
}

# Build optimized container images
build_images() {
    log "Building optimized production images..."
    
    cd "$PROJECT_ROOT"
    
    # Build multi-stage optimized image
    docker build \
        --file Dockerfile.production \
        --tag "$DOCKER_REGISTRY/provenance-linker:$IMAGE_TAG" \
        --build-arg VERSION="$(git describe --tags --always --dirty)" \
        --build-arg COMMIT="$(git rev-parse HEAD)" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --target production \
        .
    
    # Build separate images for different components if needed
    docker build \
        --file Dockerfile.cli \
        --tag "$DOCKER_REGISTRY/provenance-linker-cli:$IMAGE_TAG" \
        --build-arg VERSION="$(git describe --tags --always --dirty)" \
        .
    
    success "Images built successfully"
}

# Push images to registry
push_images() {
    log "Pushing images to registry..."
    
    docker push "$DOCKER_REGISTRY/provenance-linker:$IMAGE_TAG"
    docker push "$DOCKER_REGISTRY/provenance-linker-cli:$IMAGE_TAG"
    
    success "Images pushed successfully"
}

# Deploy infrastructure components
deploy_infrastructure() {
    log "Deploying infrastructure components..."
    
    # Create namespace
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy Neo4j with clustering
    helm upgrade --install neo4j bitnami/neo4j \
        --namespace "$NAMESPACE" \
        --set auth.enabled=true \
        --set auth.neo4j.password="$(kubectl get secret --namespace $NAMESPACE neo4j-auth -o jsonpath="{.data.neo4j-password}" 2>/dev/null | base64 -d || echo 'production-secret')" \
        --set core.numberOfServers=3 \
        --set readReplica.numberOfServers=2 \
        --set persistence.enabled=true \
        --set persistence.size=100Gi \
        --set resources.requests.memory=4Gi \
        --set resources.requests.cpu=2 \
        --set resources.limits.memory=8Gi \
        --set resources.limits.cpu=4 \
        --wait
    
    # Deploy Redis with clustering
    helm upgrade --install redis bitnami/redis \
        --namespace "$NAMESPACE" \
        --set architecture=replication \
        --set auth.enabled=true \
        --set auth.password="$(kubectl get secret --namespace $NAMESPACE redis -o jsonpath="{.data.redis-password}" 2>/dev/null | base64 -d || echo 'production-secret')" \
        --set master.persistence.enabled=true \
        --set master.persistence.size=50Gi \
        --set replica.replicaCount=2 \
        --set replica.persistence.enabled=true \
        --set replica.persistence.size=50Gi \
        --set sentinel.enabled=true \
        --set metrics.enabled=true \
        --wait
    
    # Deploy monitoring stack
    deploy_monitoring
    
    success "Infrastructure deployed successfully"
}

# Deploy monitoring and observability
deploy_monitoring() {
    log "Deploying monitoring and observability stack..."
    
    # Add monitoring repositories
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo add jaegertracing https://jaegertracing.github.io/helm-charts
    helm repo update
    
    # Deploy Prometheus
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace monitoring \
        --create-namespace \
        --set prometheus.prometheusSpec.retention=15d \
        --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=100Gi \
        --set grafana.adminPassword="admin-$(openssl rand -hex 8)" \
        --set grafana.persistence.enabled=true \
        --set grafana.persistence.size=10Gi \
        --wait
    
    # Deploy Jaeger for distributed tracing
    helm upgrade --install jaeger jaegertracing/jaeger \
        --namespace monitoring \
        --set provisionDataStore.cassandra=false \
        --set provisionDataStore.elasticsearch=true \
        --set storage.type=elasticsearch \
        --wait
    
    # Apply ServiceMonitor for our application
    kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: provenance-linker
  namespace: $NAMESPACE
spec:
  selector:
    matchLabels:
      app: provenance-linker
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
EOF
    
    success "Monitoring stack deployed"
}

# Deploy the main application
deploy_application() {
    log "Deploying provenance-linker application..."
    
    # Apply ConfigMap for application configuration
    kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: provenance-linker-config
  namespace: $NAMESPACE
data:
  config.yaml: |
$(sed 's/^/    /' "$PROJECT_ROOT/config/production.yaml")
EOF
    
    # Apply Secret for sensitive configuration
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: provenance-linker-secrets
  namespace: $NAMESPACE
type: Opaque
data:
  jwt-secret: $(echo -n "$(openssl rand -hex 32)" | base64)
  neo4j-password: $(kubectl get secret --namespace $NAMESPACE neo4j-auth -o jsonpath="{.data.neo4j-password}")
  redis-password: $(kubectl get secret --namespace $NAMESPACE redis -o jsonpath="{.data.redis-password}")
EOF
    
    # Deploy the application
    kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: provenance-linker
  namespace: $NAMESPACE
  labels:
    app: provenance-linker
    version: $IMAGE_TAG
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: provenance-linker
  template:
    metadata:
      labels:
        app: provenance-linker
        version: $IMAGE_TAG
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: provenance-linker
        image: $DOCKER_REGISTRY/provenance-linker:$IMAGE_TAG
        ports:
        - name: http
          containerPort: 8080
        - name: metrics
          containerPort: 8080
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: provenance-linker-secrets
              key: jwt-secret
        - name: NEO4J_PASSWORD
          valueFrom:
            secretKeyRef:
              name: provenance-linker-secrets
              key: neo4j-password
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: provenance-linker-secrets
              key: redis-password
        volumeMounts:
        - name: config
          mountPath: /app/config
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          successThreshold: 1
          failureThreshold: 3
      volumes:
      - name: config
        configMap:
          name: provenance-linker-config
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - provenance-linker
              topologyKey: kubernetes.io/hostname
---
apiVersion: v1
kind: Service
metadata:
  name: provenance-linker
  namespace: $NAMESPACE
  labels:
    app: provenance-linker
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 80
    targetPort: 8080
    protocol: TCP
  - name: metrics
    port: 8080
    targetPort: 8080
    protocol: TCP
  selector:
    app: provenance-linker
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: provenance-linker
  namespace: $NAMESPACE
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - provenance.danieleschmidt.com
    secretName: provenance-linker-tls
  rules:
  - host: provenance.danieleschmidt.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: provenance-linker
            port:
              number: 80
EOF
    
    success "Application deployed successfully"
}

# Deploy autoscaling
deploy_autoscaling() {
    log "Setting up autoscaling..."
    
    # Deploy Horizontal Pod Autoscaler
    kubectl apply -f - <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: provenance-linker-hpa
  namespace: $NAMESPACE
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: provenance-linker
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "100"
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
      - type: Pods
        value: 2
        periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
EOF
    
    # Deploy Vertical Pod Autoscaler (if available)
    if kubectl get crd verticalpodautoscalers.autoscaling.k8s.io &> /dev/null; then
        kubectl apply -f - <<EOF
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: provenance-linker-vpa
  namespace: $NAMESPACE
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: provenance-linker
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: provenance-linker
      minAllowed:
        cpu: 100m
        memory: 128Mi
      maxAllowed:
        cpu: 2
        memory: 4Gi
      controlledResources: ["cpu", "memory"]
EOF
    fi
    
    success "Autoscaling configured"
}

# Run post-deployment validation
validate_deployment() {
    log "Validating deployment..."
    
    # Wait for deployment to be ready
    kubectl rollout status deployment/provenance-linker -n "$NAMESPACE" --timeout=600s
    
    # Check pod health
    if ! kubectl get pods -n "$NAMESPACE" -l app=provenance-linker | grep -q "Running"; then
        error "No running pods found"
        kubectl get pods -n "$NAMESPACE" -l app=provenance-linker
        exit 1
    fi
    
    # Test service connectivity
    local service_ip
    service_ip=$(kubectl get service provenance-linker -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    
    # Port-forward to test health endpoint
    kubectl port-forward service/provenance-linker 8080:80 -n "$NAMESPACE" &
    local port_forward_pid=$!
    
    sleep 5
    
    if curl -f -s "http://localhost:8080/health" > /dev/null; then
        success "Health check passed"
    else
        error "Health check failed"
        kill $port_forward_pid 2>/dev/null || true
        exit 1
    fi
    
    kill $port_forward_pid 2>/dev/null || true
    
    # Check HPA status
    kubectl get hpa provenance-linker-hpa -n "$NAMESPACE"
    
    success "Deployment validation completed"
}

# Generate deployment report
generate_report() {
    log "Generating deployment report..."
    
    local report_file="/tmp/deployment-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" <<EOF
# Provenance Graph SBOM Linker - Production Deployment Report
Generated: $(date)
Environment: $DEPLOYMENT_ENV
Namespace: $NAMESPACE
Image Tag: $IMAGE_TAG

## Deployment Status
$(kubectl get deployment provenance-linker -n "$NAMESPACE" -o wide)

## Pod Status
$(kubectl get pods -n "$NAMESPACE" -l app=provenance-linker -o wide)

## Service Status
$(kubectl get service provenance-linker -n "$NAMESPACE" -o wide)

## Ingress Status
$(kubectl get ingress provenance-linker -n "$NAMESPACE" -o wide)

## HPA Status
$(kubectl get hpa provenance-linker-hpa -n "$NAMESPACE" -o wide)

## Infrastructure Status
### Neo4j
$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=neo4j -o wide)

### Redis
$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=redis -o wide)

## Resource Usage
$(kubectl top pods -n "$NAMESPACE" -l app=provenance-linker || echo "Metrics not available")

## Configuration
$(kubectl describe configmap provenance-linker-config -n "$NAMESPACE")

## Access Information
Application URL: https://provenance.danieleschmidt.com
Metrics URL: https://provenance.danieleschmidt.com/metrics
Health Check: https://provenance.danieleschmidt.com/health

## Next Steps
1. Monitor application metrics in Grafana
2. Set up alerting rules in Prometheus
3. Configure backup policies for Neo4j and Redis
4. Review and adjust autoscaling policies based on traffic patterns
5. Schedule regular security scans and updates

EOF
    
    success "Deployment report generated: $report_file"
    cat "$report_file"
}

# Main deployment function
main() {
    log "Starting Generation 3 production deployment..."
    log "Environment: $DEPLOYMENT_ENV"
    log "Registry: $DOCKER_REGISTRY"
    log "Image Tag: $IMAGE_TAG"
    log "Namespace: $NAMESPACE"
    
    check_prerequisites
    build_images
    push_images
    deploy_infrastructure
    deploy_application
    deploy_autoscaling
    validate_deployment
    generate_report
    
    success "🚀 Generation 3 deployment completed successfully!"
    success "Application is now available at: https://provenance.danieleschmidt.com"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi