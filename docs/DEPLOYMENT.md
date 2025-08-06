# Deployment Guide

This guide covers deployment options for the Provenance Graph SBOM Linker.

## Prerequisites

- Docker 20.10+
- Kubernetes 1.24+ (for Kubernetes deployment)
- Helm 3.8+ (for Helm deployment)
- Neo4j 5.0+ (database)
- Redis 7.0+ (caching)

## Docker Deployment

### Single Container

```bash
# Pull the latest image
docker pull ghcr.io/danieleschmidt/provenance-graph-sbom-linker:latest

# Run with minimal configuration
docker run -p 8080:8080 \
  -e DATABASE_URI=bolt://localhost:7687 \
  -e DATABASE_USERNAME=neo4j \
  -e DATABASE_PASSWORD=password \
  ghcr.io/danieleschmidt/provenance-graph-sbom-linker:latest
```

### Docker Compose

```bash
# Start the full stack
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

The `docker-compose.yml` includes:
- Provenance Linker API server
- Neo4j database
- Redis cache
- Prometheus monitoring
- Grafana dashboards

## Kubernetes Deployment

### Prerequisites

```bash
# Create namespace
kubectl create namespace provenance-system

# Create secrets
kubectl create secret generic provenance-secrets \
  --from-literal=database-uri=bolt://neo4j:7687 \
  --from-literal=database-username=neo4j \
  --from-literal=database-password=your-secure-password \
  --from-literal=jwt-secret=your-jwt-secret \
  -n provenance-system
```

### Deploy with kubectl

```bash
# Deploy all components
kubectl apply -f deploy/kubernetes/

# Check deployment status
kubectl get pods -n provenance-system

# Access the service
kubectl port-forward svc/provenance-linker 8080:8080 -n provenance-system
```

### Deploy with Helm

```bash
# Add Helm repository (if available)
helm repo add danieleschmidt https://charts.danieleschmidt.com
helm repo update

# Install with default values
helm install provenance-linker danieleschmidt/provenance-graph-sbom-linker \
  --namespace provenance-system \
  --create-namespace

# Install with custom values
helm install provenance-linker danieleschmidt/provenance-graph-sbom-linker \
  --namespace provenance-system \
  --create-namespace \
  --values values-production.yaml
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `GIN_MODE` | Gin mode (debug/release) | `release` | No |
| `LOG_LEVEL` | Log level (debug/info/warn/error) | `info` | No |
| `SERVER_PORT` | Server port | `8080` | No |
| `DATABASE_URI` | Neo4j connection URI | `bolt://localhost:7687` | Yes |
| `DATABASE_USERNAME` | Neo4j username | `neo4j` | Yes |
| `DATABASE_PASSWORD` | Neo4j password | | Yes |
| `REDIS_HOST` | Redis host | `localhost` | No |
| `REDIS_PORT` | Redis port | `6379` | No |
| `JWT_SECRET` | JWT signing secret | | Yes |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry endpoint | | No |

### Configuration File

Create `/etc/provenance-linker/config.yaml`:

```yaml
server:
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  environment: production

database:
  uri: bolt://neo4j:7687
  username: neo4j
  password: secure-password

redis:
  host: redis
  port: 6379
  db: 0

security:
  jwt_secret: your-jwt-secret
  cors_origins:
    - "https://your-domain.com"

logging:
  level: info
  format: json
```

## Scaling

### Horizontal Scaling

```yaml
# In your deployment.yaml
spec:
  replicas: 5  # Scale to 5 instances

  resources:
    requests:
      cpu: 200m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 1Gi
```

### Vertical Scaling

```yaml
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 2Gi
```

### Database Scaling

For Neo4j clustering:

```yaml
# values.yaml for Neo4j Helm chart
neo4j:
  core:
    numberOfServers: 3
  readReplica:
    numberOfServers: 2
```

## Monitoring

### Prometheus Metrics

The application exposes metrics on `/metrics` endpoint:

- `provenance_artifacts_total`
- `provenance_verifications_total`
- `provenance_sbom_vulnerabilities`
- `http_request_duration_seconds`
- `http_requests_total`

### Grafana Dashboard

Import the provided dashboard from `observability/grafana-dashboard.json`.

### Alerting

Configure alerts for:

- High error rate
- Slow response times
- Database connection issues
- Memory usage
- Certificate expiration

## Security

### TLS Configuration

```yaml
# In your ingress configuration
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: provenance-linker-ingress
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - provenance.your-domain.com
    secretName: provenance-tls
```

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: provenance-linker-netpol
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
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
```

### Pod Security

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  fsGroup: 65534
  seccompProfile:
    type: RuntimeDefault
```

## Backup and Disaster Recovery

### Database Backup

```bash
# Neo4j backup
docker exec neo4j-container neo4j-admin database backup neo4j --to-path=/backups

# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
kubectl exec -it neo4j-0 -n provenance-system -- \
  neo4j-admin database backup neo4j --to-path=/backups/backup_$DATE
```

### Configuration Backup

```bash
# Backup Kubernetes resources
kubectl get all,secrets,configmaps -n provenance-system -o yaml > backup.yaml

# Backup with specific labels
kubectl get all -l app.kubernetes.io/name=provenance-graph-sbom-linker -o yaml > app-backup.yaml
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   ```bash
   # Check Neo4j status
   kubectl logs -n provenance-system deployment/neo4j
   
   # Test connection
   kubectl exec -it provenance-linker-xxx -n provenance-system -- \
     curl bolt://neo4j:7687
   ```

2. **High Memory Usage**
   ```bash
   # Check memory metrics
   kubectl top pods -n provenance-system
   
   # Adjust memory limits
   kubectl patch deployment provenance-linker -n provenance-system -p \
     '{"spec":{"template":{"spec":{"containers":[{"name":"provenance-linker","resources":{"limits":{"memory":"2Gi"}}}]}}}}'
   ```

3. **Slow Response Times**
   ```bash
   # Check metrics
   curl http://localhost:8080/metrics | grep http_request_duration
   
   # Enable debug logging
   kubectl set env deployment/provenance-linker LOG_LEVEL=debug -n provenance-system
   ```

### Debug Commands

```bash
# Get detailed pod information
kubectl describe pod provenance-linker-xxx -n provenance-system

# Access pod shell
kubectl exec -it provenance-linker-xxx -n provenance-system -- /bin/sh

# Port forward for debugging
kubectl port-forward svc/provenance-linker 8080:8080 -n provenance-system

# Check service endpoints
kubectl get endpoints provenance-linker -n provenance-system
```

## Performance Tuning

### Application Settings

```yaml
# Increase worker processes
env:
- name: GOMAXPROCS
  value: "4"
- name: GOGC
  value: "100"

# Redis caching
- name: REDIS_MAX_CONNECTIONS
  value: "100"
- name: CACHE_TTL
  value: "3600"
```

### Database Optimization

```cypher
// Create indexes for better performance
CREATE INDEX artifact_name_index FOR (a:Artifact) ON (a.name);
CREATE INDEX source_url_index FOR (s:Source) ON (s.url);
CREATE INDEX component_name_index FOR (c:Component) ON (c.name);
```

### Load Testing

```bash
# Install k6
curl https://github.com/grafana/k6/releases/download/v0.45.0/k6-v0.45.0-linux-amd64.tar.gz -L | tar xvz

# Run load test
k6 run --vus 50 --duration 5m test/performance/api-load-test.js
```

## Maintenance

### Rolling Updates

```bash
# Update image
kubectl set image deployment/provenance-linker \
  provenance-linker=ghcr.io/danieleschmidt/provenance-graph-sbom-linker:v2.0.0 \
  -n provenance-system

# Check rollout status
kubectl rollout status deployment/provenance-linker -n provenance-system
```

### Health Checks

```bash
# Application health
curl http://localhost:8080/health

# Readiness check
curl http://localhost:8080/ready

# Metrics endpoint
curl http://localhost:8080/metrics
```

For more detailed deployment configurations, see the `deploy/` directory in the repository.