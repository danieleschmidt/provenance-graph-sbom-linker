# Deployment Guide

This guide covers comprehensive deployment strategies for the Provenance Graph SBOM Linker across different environments and platforms.

## Table of Contents

- [Deployment Overview](#deployment-overview)
- [Local Development](#local-development)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Provider Deployments](#cloud-provider-deployments)
- [High Availability Setup](#high-availability-setup)
- [Security Hardening](#security-hardening)
- [Monitoring and Observability](#monitoring-and-observability)
- [Backup and Recovery](#backup-and-recovery)

## Deployment Overview

### Architecture Components

The Provenance Graph SBOM Linker consists of several key components:

- **API Gateway**: Entry point for all requests
- **Core Services**: Provenance, SBOM, Signature, Compliance services
- **Graph Database**: Neo4j for storing provenance relationships
- **Cache Layer**: Redis for performance optimization
- **Object Storage**: Artifact and SBOM storage
- **Message Queue**: Asynchronous task processing

### Deployment Patterns

1. **Single-Node**: Development and testing
2. **Multi-Node**: Production with high availability
3. **Microservices**: Cloud-native with container orchestration
4. **Hybrid**: Mix of cloud and on-premises components

## Local Development

### Prerequisites

- Docker and Docker Compose
- Git
- Make (optional)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/provenance-graph-sbom-linker
cd provenance-graph-sbom-linker

# Start all services
docker-compose up -d

# Verify deployment
curl http://localhost:8080/health
```

### Development Environment

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  provenance-service:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "8080:8080"
    environment:
      - ENV=development
      - NEO4J_URI=bolt://neo4j:7687
      - REDIS_URL=redis://redis:6379
    volumes:
      - .:/app
      - /app/vendor
    depends_on:
      - neo4j
      - redis

  neo4j:
    image: neo4j:5.15
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      - NEO4J_AUTH=neo4j/development
      - NEO4J_PLUGINS=["apoc"]
    volumes:
      - neo4j_data:/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  neo4j_data:
  redis_data:
```

### Development Workflow

```bash
# Start development environment
make dev-up

# Run tests
make test

# Run linting
make lint

# Build and test locally
make build
make integration-test

# Stop development environment
make dev-down
```

## Docker Deployment

### Single Container Deployment

```bash
# Build the image
docker build -t provenance-linker:latest .

# Run with external dependencies
docker run -d \
  --name provenance-linker \
  -p 8080:8080 \
  -e NEO4J_URI=bolt://neo4j-host:7687 \
  -e NEO4J_USERNAME=neo4j \
  -e NEO4J_PASSWORD=password \
  -e REDIS_URL=redis://redis-host:6379 \
  provenance-linker:latest
```

### Docker Compose Production

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  provenance-service:
    image: your-org/provenance-linker:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - ENV=production
      - NEO4J_URI=bolt://neo4j:7687
      - NEO4J_USERNAME=neo4j
      - NEO4J_PASSWORD_FILE=/run/secrets/neo4j_password
      - REDIS_URL=redis://redis:6379
      - STORAGE_ENDPOINT=http://minio:9000
      - STORAGE_ACCESS_KEY_FILE=/run/secrets/storage_access_key
      - STORAGE_SECRET_KEY_FILE=/run/secrets/storage_secret_key
    secrets:
      - neo4j_password
      - storage_access_key
      - storage_secret_key
    depends_on:
      - neo4j
      - redis
      - minio
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  neo4j:
    image: neo4j:5.15-enterprise
    restart: unless-stopped
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      - NEO4J_AUTH=neo4j/$(cat /run/secrets/neo4j_password)
      - NEO4J_PLUGINS=["apoc", "graph-data-science"]
      - NEO4J_dbms_security_procedures_unrestricted=apoc.*,gds.*
    secrets:
      - neo4j_password
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass $(cat /run/secrets/redis_password)
    secrets:
      - redis_password
    volumes:
      - redis_data:/data

  minio:
    image: minio/minio:latest
    restart: unless-stopped
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      - MINIO_ROOT_USER_FILE=/run/secrets/storage_access_key
      - MINIO_ROOT_PASSWORD_FILE=/run/secrets/storage_secret_key
    secrets:
      - storage_access_key
      - storage_secret_key
    volumes:
      - minio_data:/data
    command: server /data --console-address ":9001"

secrets:
  neo4j_password:
    file: ./secrets/neo4j_password.txt
  redis_password:
    file: ./secrets/redis_password.txt
  storage_access_key:
    file: ./secrets/storage_access_key.txt
  storage_secret_key:
    file: ./secrets/storage_secret_key.txt

volumes:
  neo4j_data:
  neo4j_logs:
  redis_data:
  minio_data:
```

## Kubernetes Deployment

### Namespace Setup

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: provenance-system
  labels:
    name: provenance-system
    security.istio.io/tlsMode: istio
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: provenance-quota
  namespace: provenance-system
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    persistentvolumeclaims: "10"
```

### ConfigMap and Secrets

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: provenance-config
  namespace: provenance-system
data:
  config.yaml: |
    server:
      port: 8080
      host: 0.0.0.0
    
    database:
      type: neo4j
      max_connections: 50
      connection_timeout: 30s
    
    cache:
      type: redis
      ttl: 1h
    
    storage:
      type: s3
      bucket: provenance-artifacts
    
    observability:
      metrics:
        enabled: true
        port: 9090
      tracing:
        enabled: true
        endpoint: http://jaeger-collector:14268/api/traces
---
apiVersion: v1
kind: Secret
metadata:
  name: provenance-secrets
  namespace: provenance-system
type: Opaque
data:
  neo4j-username: bmVvNGo=  # neo4j
  neo4j-password: cGFzc3dvcmQ=  # password
  redis-password: cmVkaXNwYXNz  # redispass
  storage-access-key: YWNjZXNza2V5  # accesskey
  storage-secret-key: c2VjcmV0a2V5  # secretkey
```

### Core Service Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: provenance-service
  namespace: provenance-system
  labels:
    app: provenance-service
    version: v1
spec:
  replicas: 3
  selector:
    matchLabels:
      app: provenance-service
  template:
    metadata:
      labels:
        app: provenance-service
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: provenance-service
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: provenance-service
        image: your-org/provenance-linker:v1.0.0
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: metrics
        env:
        - name: ENV
          value: "production"
        - name: NEO4J_URI
          value: "bolt://neo4j:7687"
        - name: NEO4J_USERNAME
          valueFrom:
            secretKeyRef:
              name: provenance-secrets
              key: neo4j-username
        - name: NEO4J_PASSWORD
          valueFrom:
            secretKeyRef:
              name: provenance-secrets
              key: neo4j-password
        - name: REDIS_URL
          value: "redis://redis:6379"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: provenance-secrets
              key: redis-password
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        - name: temp
          mountPath: /tmp
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
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
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: provenance-config
      - name: temp
        emptyDir: {}
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
                  - provenance-service
              topologyKey: kubernetes.io/hostname
```

### Service and Ingress

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: provenance-service
  namespace: provenance-system
  labels:
    app: provenance-service
spec:
  selector:
    app: provenance-service
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: provenance-ingress
  namespace: provenance-system
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - provenance.your-domain.com
    secretName: provenance-tls
  rules:
  - host: provenance.your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: provenance-service
            port:
              number: 80
```

### Database Deployment

```yaml
# neo4j.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: neo4j
  namespace: provenance-system
spec:
  serviceName: neo4j
  replicas: 3
  selector:
    matchLabels:
      app: neo4j
  template:
    metadata:
      labels:
        app: neo4j
    spec:
      containers:
      - name: neo4j
        image: neo4j:5.15-enterprise
        ports:
        - containerPort: 7474
          name: http
        - containerPort: 7687
          name: bolt
        - containerPort: 6362
          name: backup
        env:
        - name: NEO4J_AUTH
          valueFrom:
            secretKeyRef:
              name: provenance-secrets
              key: neo4j-auth
        - name: NEO4J_PLUGINS
          value: '["apoc", "graph-data-science"]'
        - name: NEO4J_dbms_mode
          value: CORE
        - name: NEO4J_causal__clustering_initial__discovery__members
          value: neo4j-0.neo4j:5000,neo4j-1.neo4j:5000,neo4j-2.neo4j:5000
        volumeMounts:
        - name: data
          mountPath: /data
        - name: logs
          mountPath: /logs
        resources:
          requests:
            memory: "2Gi"
            cpu: "500m"
          limits:
            memory: "4Gi"
            cpu: "1"
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 100Gi
  - metadata:
      name: logs
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

## Cloud Provider Deployments

### AWS EKS Deployment

```bash
# Create EKS cluster
eksctl create cluster \
  --name provenance-cluster \
  --version 1.28 \
  --region us-west-2 \
  --nodegroup-name standard-workers \
  --node-type m5.large \
  --nodes 3 \
  --nodes-min 1 \
  --nodes-max 4 \
  --managed

# Install AWS Load Balancer Controller
kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller//crds?ref=master"

# Deploy the application
kubectl apply -f k8s/aws/
```

### Azure AKS Deployment

```bash
# Create AKS cluster
az aks create \
  --resource-group provenance-rg \
  --name provenance-cluster \
  --node-count 3 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Get credentials
az aks get-credentials \
  --resource-group provenance-rg \
  --name provenance-cluster

# Deploy the application
kubectl apply -f k8s/azure/
```

### Google GKE Deployment

```bash
# Create GKE cluster
gcloud container clusters create provenance-cluster \
  --num-nodes=3 \
  --zone=us-central1-a \
  --enable-autoscaling \
  --min-nodes=1 \
  --max-nodes=5

# Get credentials
gcloud container clusters get-credentials provenance-cluster --zone=us-central1-a

# Deploy the application
kubectl apply -f k8s/gcp/
```

## High Availability Setup

### Multi-Region Deployment

```yaml
# multi-region-deployment.yaml
apiVersion: v1
kind: Service
metadata:
  name: provenance-global
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled: "true"
spec:
  type: LoadBalancer
  selector:
    app: provenance-service
  ports:
  - port: 80
    targetPort: 8080
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: provenance-service
spec:
  host: provenance-service
  trafficPolicy:
    loadBalancer:
      simple: LEAST_CONN
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 10
        maxRequestsPerConnection: 2
    circuitBreaker:
      consecutiveErrors: 3
      interval: 30s
      baseEjectionTime: 30s
```

### Database Clustering

```yaml
# neo4j-cluster.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: neo4j-core
spec:
  serviceName: neo4j-core
  replicas: 3
  template:
    spec:
      containers:
      - name: neo4j
        image: neo4j:5.15-enterprise
        env:
        - name: NEO4J_dbms_mode
          value: CORE
        - name: NEO4J_causal__clustering_minimum__core__cluster__size__at__formation
          value: "3"
        - name: NEO4J_causal__clustering_minimum__core__cluster__size__at__runtime
          value: "3"
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: neo4j-replica
spec:
  serviceName: neo4j-replica
  replicas: 2
  template:
    spec:
      containers:
      - name: neo4j
        image: neo4j:5.15-enterprise
        env:
        - name: NEO4J_dbms_mode
          value: READ_REPLICA
```

## Security Hardening

### Network Policies

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: provenance-network-policy
  namespace: provenance-system
spec:
  podSelector:
    matchLabels:
      app: provenance-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: istio-system
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: neo4j
    ports:
    - protocol: TCP
      port: 7687
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
```

### Pod Security Policy

```yaml
# pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: provenance-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

## Monitoring and Observability

### Prometheus Configuration

```yaml
# prometheus-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    
    scrape_configs:
    - job_name: 'provenance-service'
      kubernetes_sd_configs:
      - role: endpoints
      relabel_configs:
      - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
```

### Grafana Dashboards

```json
{
  "dashboard": {
    "title": "Provenance Service Overview",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [{
          "expr": "rate(http_requests_total[5m])",
          "legendFormat": "{{method}} {{status}}"
        }]
      },
      {
        "title": "Response Time",
        "targets": [{
          "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
          "legendFormat": "95th percentile"
        }]
      },
      {
        "title": "Database Connections",
        "targets": [{
          "expr": "neo4j_database_pool_total_used",
          "legendFormat": "Used connections"
        }]
      }
    ]
  }
}
```

## Backup and Recovery

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"
NEO4J_CONTAINER="neo4j-0"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup Neo4j database
kubectl exec $NEO4J_CONTAINER -n provenance-system -- \
  neo4j-admin database backup \
  --to-path=/var/backups \
  --database=neo4j \
  --verbose

# Copy backup to persistent storage
kubectl cp provenance-system/$NEO4J_CONTAINER:/var/backups \
  $BACKUP_DIR/neo4j_$DATE

# Backup object storage
aws s3 sync s3://provenance-artifacts $BACKUP_DIR/artifacts_$DATE

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -type d -mtime +7 -exec rm -rf {} \;

echo "Backup completed: $DATE"
```

### Disaster Recovery Plan

1. **Recovery Time Objective (RTO)**: 4 hours
2. **Recovery Point Objective (RPO)**: 1 hour
3. **Automated Failover**: Cross-region deployment
4. **Data Validation**: Integrity checks after recovery

```bash
#!/bin/bash
# disaster-recovery.sh

# Restore from backup
kubectl create namespace provenance-system-recovery

# Restore database
kubectl exec neo4j-0 -n provenance-system-recovery -- \
  neo4j-admin database restore \
  --from-path=/var/backups/neo4j_latest \
  --database=neo4j

# Restore object storage
aws s3 sync $BACKUP_DIR/artifacts_latest s3://provenance-artifacts-recovery

# Update DNS to point to recovery environment
kubectl patch ingress provenance-ingress \
  -n provenance-system-recovery \
  --type='json' \
  -p='[{"op": "replace", "path": "/spec/rules/0/host", "value": "provenance.your-domain.com"}]'

echo "Disaster recovery completed"
```

This deployment guide provides comprehensive instructions for deploying the Provenance Graph SBOM Linker across various environments while maintaining security, scalability, and reliability standards.