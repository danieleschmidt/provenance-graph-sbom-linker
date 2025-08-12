# Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Provenance Graph SBOM Linker to production environments. The system supports multiple deployment patterns including containerized, Kubernetes, and cloud-native deployments.

## Prerequisites

### System Requirements

**Minimum Requirements:**
- CPU: 2 cores
- RAM: 4GB
- Storage: 20GB
- Network: 1Gbps

**Recommended Production:**
- CPU: 8 cores
- RAM: 16GB
- Storage: 100GB SSD
- Network: 10Gbps

### Dependencies

- **Go**: 1.23 or later
- **Neo4j**: 5.x (for graph database)
- **Redis**: 7.x (for caching)
- **Docker**: 24.x (for containerized deployment)
- **Kubernetes**: 1.28+ (for orchestrated deployment)

## Configuration

### Environment Variables

```bash
# Application Configuration
APP_ENV=production
APP_PORT=8080
APP_LOG_LEVEL=info

# Database Configuration
NEO4J_URI=bolt://neo4j:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=<secure-password>

# Redis Configuration
REDIS_ADDR=redis:6379
REDIS_PASSWORD=<secure-password>
REDIS_DB=0

# Authentication
JWT_SECRET=<generate-secure-secret>
JWT_EXPIRY=24h

# Monitoring
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318
OTEL_SERVICE_NAME=provenance-linker
METRICS_ENABLED=true

# Performance
WORKER_COUNT=10
CACHE_TTL=3600
MAX_CONNECTIONS=25
```

### Configuration Files

Create `config/production.yaml`:

```yaml
server:
  port: 8080
  read_timeout: 30s
  write_timeout: 30s
  shutdown_timeout: 30s

database:
  neo4j:
    uri: ${NEO4J_URI}
    username: ${NEO4J_USERNAME}
    password: ${NEO4J_PASSWORD}
    max_connections: 25
    connection_timeout: 30s
  
  redis:
    addr: ${REDIS_ADDR}
    password: ${REDIS_PASSWORD}
    db: ${REDIS_DB}
    pool_size: 25

security:
  jwt:
    secret: ${JWT_SECRET}
    expiry: ${JWT_EXPIRY}
  
  rate_limiting:
    enabled: true
    requests_per_minute: 100
  
  cors:
    allowed_origins: ["https://your-domain.com"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE"]

monitoring:
  metrics_enabled: true
  tracing_enabled: true
  health_check_interval: 30s
  
  otel:
    endpoint: ${OTEL_EXPORTER_OTLP_ENDPOINT}
    service_name: ${OTEL_SERVICE_NAME}

performance:
  worker_count: ${WORKER_COUNT}
  cache_ttl: ${CACHE_TTL}
  memory_pool_size: 1000
  max_memory_usage: 1073741824  # 1GB
```

## Deployment Options

### Option 1: Docker Compose (Recommended for Development/Testing)

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.prod
    ports:
      - "8080:8080"
    environment:
      - APP_ENV=production
      - NEO4J_URI=bolt://neo4j:7687
      - REDIS_ADDR=redis:6379
    depends_on:
      - neo4j
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  neo4j:
    image: neo4j:5.14
    environment:
      - NEO4J_AUTH=neo4j/secure-password
      - NEO4J_PLUGINS=["apoc"]
    ports:
      - "7474:7474"
      - "7687:7687"
    volumes:
      - neo4j_data:/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass secure-password
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
    restart: unless-stopped

volumes:
  neo4j_data:
  redis_data:
  grafana_data:
```

### Option 2: Kubernetes Deployment

Create Kubernetes manifests in `k8s/`:

**Namespace:**
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: provenance-linker
```

**ConfigMap:**
```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: provenance-linker
data:
  production.yaml: |
    server:
      port: 8080
    # ... rest of config
```

**Secret:**
```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: provenance-linker
type: Opaque
data:
  jwt-secret: <base64-encoded-secret>
  neo4j-password: <base64-encoded-password>
  redis-password: <base64-encoded-password>
```

**Deployment:**
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: provenance-linker
  namespace: provenance-linker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: provenance-linker
  template:
    metadata:
      labels:
        app: provenance-linker
    spec:
      containers:
      - name: app
        image: provenance-linker:latest
        ports:
        - containerPort: 8080
        env:
        - name: APP_ENV
          value: "production"
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: jwt-secret
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
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

**Service:**
```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: provenance-linker-service
  namespace: provenance-linker
spec:
  selector:
    app: provenance-linker
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

**Ingress:**
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: provenance-linker-ingress
  namespace: provenance-linker
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - api.your-domain.com
    secretName: provenance-linker-tls
  rules:
  - host: api.your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: provenance-linker-service
            port:
              number: 80
```

### Option 3: Cloud Deployment (AWS ECS)

**Task Definition:**
```json
{
  "family": "provenance-linker",
  "networkMode": "awsvpc",
  "requiresAttributes": [
    {
      "name": "com.amazonaws.ecs.capability.docker-remote-api.1.18"
    }
  ],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "provenance-linker",
      "image": "your-account.dkr.ecr.region.amazonaws.com/provenance-linker:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "APP_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:ssm:region:account:parameter/provenance-linker/jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/provenance-linker",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:8080/health || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      }
    }
  ]
}
```

## Security Hardening

### SSL/TLS Configuration

```nginx
# nginx.conf
server {
    listen 443 ssl http2;
    server_name api.your-domain.com;

    ssl_certificate /etc/ssl/certs/your-domain.crt;
    ssl_certificate_key /etc/ssl/private/your-domain.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Network Security

- Configure firewall rules to allow only necessary ports
- Use VPC/network segmentation
- Implement WAF rules for HTTP protection
- Enable DDoS protection

### Authentication & Authorization

- Rotate JWT secrets regularly
- Implement strong password policies
- Use service accounts for inter-service communication
- Enable audit logging

## Monitoring & Observability

### Metrics Collection

Configure Prometheus to scrape metrics:

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'provenance-linker'
    static_configs:
      - targets: ['app:8080']
    metrics_path: /metrics
```

### Grafana Dashboards

Import dashboards for:
- Application metrics
- System performance
- Database health
- Cache utilization
- Error rates

### Alerting Rules

```yaml
# alerts.yml
groups:
  - name: provenance-linker
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: High error rate detected
          
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High latency detected
```

## Backup & Recovery

### Database Backup

```bash
# Neo4j backup
neo4j-admin database backup --database=neo4j --to-path=/backups

# Redis backup
redis-cli --rdb /backups/redis-backup.rdb
```

### Disaster Recovery

1. **RTO (Recovery Time Objective):** 4 hours
2. **RPO (Recovery Point Objective):** 1 hour
3. **Backup Schedule:** Daily full, hourly incremental
4. **Geographic Redundancy:** Multi-region deployment

## Performance Tuning

### Application Tuning

```yaml
# Recommended production settings
performance:
  worker_count: 16                    # 2x CPU cores
  cache_ttl: 3600                     # 1 hour
  memory_pool_size: 2000              # Double default
  max_memory_usage: 2147483648        # 2GB
  connection_pool_size: 50            # High concurrency
  batch_size: 100                     # Optimal batch size
```

### Database Tuning

**Neo4j:**
```
# neo4j.conf
dbms.memory.heap.initial_size=2g
dbms.memory.heap.max_size=4g
dbms.memory.pagecache.size=2g
dbms.transaction.timeout=60s
```

**Redis:**
```
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

## Deployment Automation

### CI/CD Pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    tags:
      - 'v*'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build and push Docker image
        run: |
          docker build -t provenance-linker:${{ github.ref_name }} .
          docker push your-registry/provenance-linker:${{ github.ref_name }}
      
      - name: Deploy to production
        run: |
          kubectl set image deployment/provenance-linker \
            app=your-registry/provenance-linker:${{ github.ref_name }}
```

### Blue-Green Deployment

```bash
#!/bin/bash
# blue-green-deploy.sh

NEW_VERSION=$1
CURRENT_ENV=$(kubectl get service provenance-linker -o jsonpath='{.spec.selector.version}')

if [ "$CURRENT_ENV" = "blue" ]; then
    NEW_ENV="green"
else
    NEW_ENV="blue"
fi

# Deploy new version
kubectl set image deployment/provenance-linker-$NEW_ENV \
  app=provenance-linker:$NEW_VERSION

# Wait for deployment
kubectl rollout status deployment/provenance-linker-$NEW_ENV

# Health check
if curl -f http://health-check-url/health; then
    # Switch traffic
    kubectl patch service provenance-linker -p '{"spec":{"selector":{"version":"'$NEW_ENV'"}}}'
    echo "Deployment successful"
else
    echo "Health check failed, rolling back"
    exit 1
fi
```

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
   - Check database connectivity
   - Verify network configuration
   - Increase timeout values

2. **High Memory Usage**
   - Monitor GC metrics
   - Adjust memory pool settings
   - Check for memory leaks

3. **Performance Degradation**
   - Review cache hit rates
   - Analyze database query performance
   - Check worker pool utilization

### Logging

```yaml
# Log levels and destinations
logging:
  level: info
  format: json
  outputs:
    - console
    - file: /var/log/provenance-linker.log
    - syslog: localhost:514
```

### Debug Mode

Enable debug mode for troubleshooting:

```bash
export APP_LOG_LEVEL=debug
export DEBUG_METRICS=true
export PROFILE_ENABLED=true
```

## Post-Deployment Checklist

- [ ] Application starts successfully
- [ ] All health checks pass
- [ ] Database connections established
- [ ] Cache connectivity verified
- [ ] Metrics collection working
- [ ] Log aggregation configured
- [ ] SSL certificate valid
- [ ] Backup procedures tested
- [ ] Monitoring alerts configured
- [ ] Load balancer health checks pass
- [ ] API endpoints responding
- [ ] Authentication working
- [ ] Performance within SLA
- [ ] Security scan passed

## Support & Maintenance

### Maintenance Schedule

- **Daily:** Health checks, log review
- **Weekly:** Performance analysis, security updates
- **Monthly:** Dependency updates, backup testing
- **Quarterly:** Security audit, disaster recovery testing

### Support Contacts

- **Technical Lead:** [Contact Information]
- **DevOps Team:** [Contact Information]
- **Security Team:** [Contact Information]
- **On-Call:** [Escalation Procedures]

---

This deployment guide ensures a secure, scalable, and maintainable production deployment of the Provenance Graph SBOM Linker system.