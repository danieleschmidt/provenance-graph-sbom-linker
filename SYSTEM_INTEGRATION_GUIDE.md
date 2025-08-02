# System Integration Guide

## Overview

This guide provides comprehensive instructions for integrating and deploying the Provenance Graph SBOM Linker system. The platform is designed as a complete supply chain security solution with enterprise-grade features.

---

## 🏗 Architecture Overview

The system consists of multiple integrated components:

### Core Components
- **API Server**: RESTful API for provenance and SBOM operations
- **Security Scanner**: Multi-engine vulnerability and compliance scanning
- **Graph Database**: Neo4j for provenance relationship storage
- **Cache Layer**: Redis for performance optimization
- **Object Storage**: MinIO/S3 for artifact and report storage

### Supporting Infrastructure
- **Monitoring Stack**: Prometheus, Grafana, Jaeger for observability
- **Metrics Collection**: Business and technical KPI tracking
- **Security Monitoring**: Real-time threat detection and alerting
- **Automation Engine**: Comprehensive operational automation

---

## 🚀 Quick Start Deployment

### Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl configured with cluster access
- Helm 3.8+
- Docker (for image building)
- 50GB+ available storage

### One-Command Deployment

```bash
# Deploy complete system to production
./scripts/system-deployment.sh deploy \
  --environment production \
  --domain provenance.company.com \
  --wait --timeout 20m

# Deploy to staging environment
./scripts/system-deployment.sh deploy \
  --environment staging \
  --namespace provenance-staging \
  --skip-validation
```

---

## 📋 Deployment Checkpoints

The system implements the following deployment checkpoints for reliable deployment:

### Checkpoint 1: Infrastructure Preparation
- Create namespace and RBAC configuration
- Deploy Neo4j database with persistence
- Deploy Redis cache with clustering
- Deploy MinIO object storage with backup

### Checkpoint 2: Monitoring Setup
- Deploy Prometheus monitoring stack
- Configure Grafana dashboards
- Setup Jaeger distributed tracing
- Enable custom metrics collection

### Checkpoint 3: Application Deployment
- Deploy main API server with scaling
- Configure ingress and TLS termination
- Setup health checks and probes
- Enable autoscaling policies

### Checkpoint 4: Security Configuration
- Apply network policies
- Configure security contexts
- Setup certificate management
- Enable audit logging

### Checkpoint 5: Validation and Testing
- Perform deployment validation
- Run integration tests
- Verify monitoring integration
- Confirm security policies

---

## 🔧 Configuration Management

### Environment Configuration

The system supports multiple environment configurations:

```yaml
# Production Configuration
environment: production
scaling:
  min_replicas: 3
  max_replicas: 10
  target_cpu: 70%
security:
  network_policies: strict
  pod_security: restricted
storage:
  persistence: enabled
  backup_retention: 90d

# Staging Configuration  
environment: staging
scaling:
  min_replicas: 1
  max_replicas: 3
  target_cpu: 80%
security:
  network_policies: permissive
  pod_security: baseline
storage:
  persistence: enabled
  backup_retention: 7d
```

### Custom Values Override

Create custom configuration files:

```bash
# Create custom values for production
cat > values-production.yaml << EOF
provenance-linker:
  image:
    tag: "v1.2.0"
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 4000m
      memory: 4Gi
  database:
    neo4j:
      persistence:
        size: 100Gi
      resources:
        memory: 8Gi
EOF

# Deploy with custom values
./scripts/system-deployment.sh deploy --values values-production.yaml
```

---

## 🔐 Security Integration

### Network Security

The system implements comprehensive network security:

```yaml
# Network Policy Example
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: provenance-security-policy
spec:
  podSelector:
    matchLabels:
      app: provenance-linker
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - protocol: TCP
          port: 8080
  egress:
    # Restricted egress to essential services only
    - to:
        - podSelector:
            matchLabels:
              app: neo4j
      ports:
        - protocol: TCP
          port: 7687
```

### Secret Management

Secrets are managed through Kubernetes secrets with encryption at rest:

```bash
# Create signing keys secret
kubectl create secret generic signing-keys \
  --from-file=private.pem=path/to/private.pem \
  --from-file=cert.pem=path/to/cert.pem \
  --namespace provenance-system

# Create database credentials
kubectl create secret generic database-credentials \
  --from-literal=neo4j-password=secure-password \
  --from-literal=redis-password=secure-password \
  --namespace provenance-system
```

### RBAC Configuration

Role-based access control is configured for least privilege access:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: provenance-linker
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create"]
  # No write access to sensitive resources
```

---

## 📊 Monitoring Integration

### Metrics and Dashboards

The system provides comprehensive monitoring:

- **Business Metrics**: Supply chain security score, vulnerability trends
- **Technical Metrics**: API performance, database latency, cache hit ratios
- **Security Metrics**: Threat detection, compliance scores, signature verification rates
- **Operational Metrics**: Deployment frequency, incident response times

### Alerting Configuration

Critical alerts are configured for:

```yaml
# Example Alert Rules
groups:
  - name: supply_chain_security
    rules:
      - alert: CriticalVulnerabilityDetected
        expr: vulnerabilities_total{severity="critical"} > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Critical vulnerability detected in supply chain"
          
      - alert: APIHighLatency
        expr: api_latency_p95 > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "API latency above acceptable threshold"
```

### Custom Dashboards

Grafana dashboards are automatically provisioned for:

- Supply Chain Security Overview
- API Performance Monitoring
- Database Performance Metrics
- Security Incident Dashboard
- Compliance Status Dashboard

---

## 🔄 Operational Procedures

### Scaling Operations

```bash
# Scale deployment
./scripts/system-deployment.sh scale --replicas 5

# Auto-scaling configuration
kubectl apply -f - << EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: provenance-linker
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: provenance-linker
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
EOF
```

### Backup and Recovery

```bash
# Create system backup
./scripts/system-deployment.sh backup

# Backup includes:
# - Kubernetes resource definitions
# - Database dumps
# - Configuration files
# - Persistent volume snapshots
```

### Rolling Updates

```bash
# Update to new version
kubectl set image deployment/provenance-linker \
  provenance-linker=ghcr.io/danieleschmidt/provenance-graph-sbom-linker:v1.3.0 \
  --namespace provenance-system

# Monitor rollout status
kubectl rollout status deployment/provenance-linker --namespace provenance-system

# Rollback if needed
./scripts/system-deployment.sh rollback --revision 2
```

---

## 🧪 Testing and Validation

### Integration Testing

Run comprehensive integration tests:

```bash
# Full integration test suite
./test/scripts/run-tests.sh --integration --e2e --environment staging

# Performance benchmarking
./scripts/performance-benchmarks.sh end-to-end --duration 600 --users 50

# Security validation
./scripts/automation-engine.sh security-scan --type all --notify
```

### Health Checks

The system provides multiple health check endpoints:

```bash
# Application health
curl -f http://provenance.company.com/health

# Readiness check
curl -f http://provenance.company.com/ready

# Metrics endpoint
curl http://provenance.company.com/metrics
```

### Load Testing

Comprehensive load testing capabilities:

```bash
# API load testing
./scripts/performance-benchmarks.sh api-load \
  --users 100 --duration 1800 --endpoint https://provenance.company.com

# SBOM processing benchmarks
./scripts/performance-benchmarks.sh sbom-processing \
  --file test/data/large-sbom.json --iterations 1000

# Concurrent scanning test
./scripts/performance-benchmarks.sh concurrent-scans \
  --concurrent 10 --duration 300
```

---

## 🔍 Troubleshooting

### Common Issues

#### Deployment Failures

```bash
# Check pod status
kubectl get pods -n provenance-system -o wide

# View pod logs
kubectl logs -f deployment/provenance-linker -n provenance-system

# Describe pod for events
kubectl describe pod -l app=provenance-linker -n provenance-system
```

#### Database Connection Issues

```bash
# Test Neo4j connectivity
kubectl exec -it deployment/provenance-linker -n provenance-system -- \
  nc -zv neo4j 7687

# Check database logs
kubectl logs -f deployment/neo4j -n provenance-system

# Verify credentials
kubectl get secret provenance-linker-secrets -n provenance-system -o yaml
```

#### Performance Issues

```bash
# Check resource utilization
kubectl top pods -n provenance-system

# View HPA status
kubectl get hpa -n provenance-system

# Check metrics
kubectl exec -it deployment/provenance-linker -n provenance-system -- \
  curl localhost:8080/metrics
```

### Debug Mode

Enable debug mode for detailed logging:

```bash
# Set debug environment variable
kubectl set env deployment/provenance-linker LOG_LEVEL=debug -n provenance-system

# View debug logs
kubectl logs -f deployment/provenance-linker -n provenance-system | grep DEBUG
```

---

## 📚 API Documentation

### Core Endpoints

The system provides a comprehensive RESTful API:

```bash
# Health and status
GET /health                 # Health check
GET /ready                  # Readiness check
GET /metrics               # Prometheus metrics

# SBOM operations
POST /api/v1/sbom          # Submit SBOM for processing
GET /api/v1/sbom/{id}      # Retrieve SBOM by ID
GET /api/v1/sbom/search    # Search SBOMs

# Vulnerability management
GET /api/v1/vulnerabilities # List vulnerabilities
GET /api/v1/scan/{id}      # Get scan results
POST /api/v1/scan          # Trigger security scan

# Provenance tracking
GET /api/v1/provenance/{id}  # Get provenance data
POST /api/v1/provenance      # Submit provenance information
GET /api/v1/graph           # Query provenance graph

# Compliance reporting
GET /api/v1/compliance      # Get compliance status
GET /api/v1/reports         # List available reports
POST /api/v1/reports        # Generate custom report
```

### Authentication

The API supports multiple authentication methods:

```bash
# JWT Token Authentication
curl -H "Authorization: Bearer <jwt-token>" \
  https://provenance.company.com/api/v1/sbom

# API Key Authentication  
curl -H "X-API-Key: <api-key>" \
  https://provenance.company.com/api/v1/vulnerabilities

# mTLS Authentication (for high-security environments)
curl --cert client.crt --key client.key \
  https://provenance.company.com/api/v1/provenance
```

---

## 🤝 Integration Examples

### CI/CD Integration

```yaml
# GitHub Actions Integration
name: Supply Chain Security Check
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Generate SBOM
        run: |
          syft . -o cyclonedx-json > sbom.json
      - name: Submit to Provenance Linker
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.PROVENANCE_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d @sbom.json \
            https://provenance.company.com/api/v1/sbom
```

### Third-Party Integrations

```bash
# Integrate with external vulnerability databases
export VULNDB_API_KEY="your-api-key"
./scripts/automation-engine.sh security-scan --type sca --external-sources

# Connect to SIEM systems
kubectl create configmap siem-config \
  --from-literal=siem-endpoint=https://your-siem.company.com \
  --from-literal=siem-api-key=your-siem-key \
  --namespace provenance-system
```

---

## 📈 Performance Optimization

### Recommended Resources

For production environments:

```yaml
# Resource recommendations by deployment size
small_deployment:  # < 1000 artifacts/day
  api_server:
    cpu: 500m
    memory: 1Gi
  database:
    cpu: 1000m
    memory: 4Gi
    storage: 50Gi

medium_deployment:  # 1000-10000 artifacts/day
  api_server:
    cpu: 2000m
    memory: 4Gi
  database:
    cpu: 4000m
    memory: 16Gi
    storage: 200Gi

large_deployment:  # > 10000 artifacts/day
  api_server:
    cpu: 4000m
    memory: 8Gi
  database:
    cpu: 8000m
    memory: 32Gi
    storage: 500Gi
```

### Performance Tuning

```bash
# Database optimization
kubectl exec -it deployment/neo4j -n provenance-system -- \
  cypher-shell "CALL dbms.procedures() YIELD name WHERE name CONTAINS 'index'"

# Cache optimization
kubectl exec -it deployment/redis -n provenance-system -- \
  redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Application tuning
kubectl set env deployment/provenance-linker \
  GOMAXPROCS=4 \
  GOMEMLIMIT=2GiB \
  --namespace provenance-system
```

---

## 🆘 Support and Maintenance

### Maintenance Schedule

Recommended maintenance activities:

- **Daily**: Health checks, log rotation, metric review
- **Weekly**: Security scans, dependency updates, backup verification
- **Monthly**: Performance benchmarks, capacity planning, security audits
- **Quarterly**: Disaster recovery testing, compliance reviews, system upgrades

### Support Contacts

- **Platform Issues**: platform-team@company.com
- **Security Incidents**: security-team@company.com  
- **Emergency Support**: +1-555-EMERGENCY

### Documentation Updates

This guide is maintained alongside the codebase. For updates:

1. Submit pull requests for documentation changes
2. Include documentation updates in feature PRs
3. Review documentation during release planning

---

**Version**: 1.0  
**Last Updated**: 2024-01-01  
**Maintained By**: Platform Security Team