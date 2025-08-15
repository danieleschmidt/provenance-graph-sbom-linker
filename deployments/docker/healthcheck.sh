#!/bin/sh

# Health check script for Self-Healing Pipeline Guard System
# TERRAGON SDLC AUTONOMOUS EXECUTION - Production Deployment

set -e

# Configuration
HEALTH_ENDPOINT="${HEALTH_ENDPOINT:-http://localhost:8080/health}"
TIMEOUT="${HEALTH_TIMEOUT:-10}"
MAX_RETRIES="${HEALTH_MAX_RETRIES:-3}"

# Health check function
check_health() {
    local attempt=1
    
    while [ $attempt -le $MAX_RETRIES ]; do
        echo "Health check attempt $attempt/$MAX_RETRIES"
        
        # Check if service is responding
        if curl -f -s --max-time $TIMEOUT "$HEALTH_ENDPOINT" > /dev/null 2>&1; then
            echo "✅ Health check passed"
            return 0
        fi
        
        echo "⚠️ Health check failed (attempt $attempt)"
        attempt=$((attempt + 1))
        
        if [ $attempt -le $MAX_RETRIES ]; then
            sleep 2
        fi
    done
    
    echo "❌ Health check failed after $MAX_RETRIES attempts"
    return 1
}

# Enhanced health check with detailed status
check_detailed_health() {
    local response
    local http_code
    
    echo "Performing detailed health check..."
    
    # Get health status with details
    response=$(curl -s --max-time $TIMEOUT -w "HTTP_CODE:%{http_code}" "$HEALTH_ENDPOINT" 2>/dev/null || echo "ERROR")
    
    if [ "$response" = "ERROR" ]; then
        echo "❌ Failed to connect to health endpoint"
        return 1
    fi
    
    http_code=$(echo "$response" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
    body=$(echo "$response" | sed 's/HTTP_CODE:[0-9]*$//')
    
    echo "HTTP Status: $http_code"
    
    if [ "$http_code" = "200" ]; then
        echo "✅ Service is healthy"
        
        # Try to parse JSON response for additional details
        if command -v jq >/dev/null 2>&1; then
            echo "Health details:"
            echo "$body" | jq . 2>/dev/null || echo "$body"
        else
            echo "Response: $body"
        fi
        
        return 0
    else
        echo "❌ Service is unhealthy (HTTP $http_code)"
        echo "Response: $body"
        return 1
    fi
}

# Check if we should run detailed health check
if [ "$1" = "--detailed" ] || [ "$DETAILED_HEALTH_CHECK" = "true" ]; then
    check_detailed_health
else
    check_health
fi