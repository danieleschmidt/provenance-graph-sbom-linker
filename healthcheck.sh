#!/bin/bash
# Health check script for provenance-graph-sbom-linker
set -e

# Configuration
HEALTH_ENDPOINT="http://localhost:8080/health"
NEO4J_ENDPOINT="bolt://localhost:7687"
REDIS_ENDPOINT="localhost:6379"
TIMEOUT=10

echo "Starting health checks..."

# Check main service health
echo "Checking main service health..."
if curl -f -s --max-time $TIMEOUT $HEALTH_ENDPOINT > /dev/null; then
    echo "✅ Main service is healthy"
else
    echo "❌ Main service health check failed"
    exit 1
fi

# Check Neo4j connectivity
echo "Checking Neo4j connectivity..."
if command -v cypher-shell &> /dev/null; then
    if echo "RETURN 1" | cypher-shell -a $NEO4J_ENDPOINT --timeout $TIMEOUT > /dev/null 2>&1; then
        echo "✅ Neo4j is accessible"
    else
        echo "❌ Neo4j connectivity failed"
        exit 1
    fi
else
    echo "⚠️  cypher-shell not available, skipping Neo4j check"
fi

# Check Redis connectivity
echo "Checking Redis connectivity..."
if command -v redis-cli &> /dev/null; then
    if redis-cli -h ${REDIS_ENDPOINT%:*} -p ${REDIS_ENDPOINT#*:} ping > /dev/null 2>&1; then
        echo "✅ Redis is accessible"
    else
        echo "❌ Redis connectivity failed"
        exit 1
    fi
else
    echo "⚠️  redis-cli not available, skipping Redis check"
fi

# Check disk space
echo "Checking disk space..."
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -lt 90 ]; then
    echo "✅ Disk space is adequate ($DISK_USAGE% used)"
else
    echo "⚠️  Disk space is running low ($DISK_USAGE% used)"
fi

# Check memory usage
echo "Checking memory usage..."
MEMORY_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ "$MEMORY_USAGE" -lt 90 ]; then
    echo "✅ Memory usage is normal ($MEMORY_USAGE% used)"
else
    echo "⚠️  Memory usage is high ($MEMORY_USAGE% used)"
fi

echo "Health checks completed successfully!"