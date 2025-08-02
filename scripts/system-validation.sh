#!/bin/bash

# System Validation Script for Provenance Graph SBOM Linker
# =============================================================================
# Comprehensive system validation and readiness verification

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VALIDATION_DIR="${PROJECT_ROOT}/validation-results"
LOG_DIR="${PROJECT_ROOT}/logs/validation"

# Default values
NAMESPACE="provenance-system"
TIMEOUT="300s"
VERBOSE=false
GENERATE_REPORT=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Setup logging
mkdir -p "${LOG_DIR}" "${VALIDATION_DIR}"
LOGFILE="${LOG_DIR}/validation-$(date +%Y%m%d-%H%M%S).log"

# Validation results
declare -A VALIDATION_RESULTS
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "${LOGFILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "${LOGFILE}"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "${LOGFILE}"
    WARNING_CHECKS=$((WARNING_CHECKS + 1))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOGFILE}"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
}

log_section() {
    echo -e "\n${PURPLE}=== $1 ===${NC}\n" | tee -a "${LOGFILE}"
}

# Record validation result
record_result() {
    local check_name="$1"
    local status="$2"
    local details="$3"
    
    VALIDATION_RESULTS["$check_name"]="$status|$details"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [options]

Comprehensive system validation for Provenance Graph SBOM Linker

OPTIONS:
    -h, --help              Show this help message
    -n, --namespace NAME    Kubernetes namespace (default: provenance-system)
    -t, --timeout DURATION  Timeout for checks (default: 300s)
    -v, --verbose           Enable verbose output
    --no-report            Skip generating validation report
    --check-only TYPE      Run only specific check type
                          (infrastructure|application|security|performance|integration)

EXAMPLES:
    $0                                    # Run all validation checks
    $0 --namespace provenance-staging     # Validate staging environment
    $0 --check-only security              # Run only security checks
    $0 --verbose --timeout 600s           # Verbose with longer timeout

EOF
}

# Validate infrastructure components
validate_infrastructure() {
    log_section "Validating Infrastructure Components"
    
    # Check namespace
    log_info "Checking namespace..."
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_success "Namespace '$NAMESPACE' exists"
        record_result "namespace_exists" "PASS" "Namespace found"
    else
        log_error "Namespace '$NAMESPACE' not found"
        record_result "namespace_exists" "FAIL" "Namespace missing"
        return 1
    fi
    
    # Check Neo4j database
    log_info "Checking Neo4j database..."
    if kubectl get deployment neo4j -n "$NAMESPACE" &> /dev/null; then
        local ready_replicas=$(kubectl get deployment neo4j -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
        local desired_replicas=$(kubectl get deployment neo4j -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
        
        if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" -gt 0 ]]; then
            log_success "Neo4j database is running ($ready_replicas/$desired_replicas replicas)"
            record_result "neo4j_status" "PASS" "$ready_replicas/$desired_replicas replicas ready"
        else
            log_error "Neo4j database not ready ($ready_replicas/$desired_replicas replicas)"
            record_result "neo4j_status" "FAIL" "Not all replicas ready"
        fi
    else
        log_error "Neo4j deployment not found"
        record_result "neo4j_status" "FAIL" "Deployment not found"
    fi
    
    # Check Redis cache
    log_info "Checking Redis cache..."
    if kubectl get deployment redis -n "$NAMESPACE" &> /dev/null; then
        local ready_replicas=$(kubectl get deployment redis -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
        local desired_replicas=$(kubectl get deployment redis -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
        
        if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" -gt 0 ]]; then
            log_success "Redis cache is running ($ready_replicas/$desired_replicas replicas)"
            record_result "redis_status" "PASS" "$ready_replicas/$desired_replicas replicas ready"
        else
            log_error "Redis cache not ready ($ready_replicas/$desired_replicas replicas)"
            record_result "redis_status" "FAIL" "Not all replicas ready"
        fi
    else
        log_error "Redis deployment not found"
        record_result "redis_status" "FAIL" "Deployment not found"
    fi
    
    # Check MinIO storage
    log_info "Checking MinIO object storage..."
    if kubectl get deployment minio -n "$NAMESPACE" &> /dev/null; then
        local ready_replicas=$(kubectl get deployment minio -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
        local desired_replicas=$(kubectl get deployment minio -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
        
        if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" -gt 0 ]]; then
            log_success "MinIO storage is running ($ready_replicas/$desired_replicas replicas)"
            record_result "minio_status" "PASS" "$ready_replicas/$desired_replicas replicas ready"
        else
            log_error "MinIO storage not ready ($ready_replicas/$desired_replicas replicas)"
            record_result "minio_status" "FAIL" "Not all replicas ready"
        fi
    else
        log_error "MinIO deployment not found"
        record_result "minio_status" "FAIL" "Deployment not found"
    fi
    
    # Check persistent volumes
    log_info "Checking persistent storage..."
    local pvc_count=$(kubectl get pvc -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
    local bound_pvc_count=$(kubectl get pvc -n "$NAMESPACE" --no-headers 2>/dev/null | grep Bound | wc -l)
    
    if [[ "$pvc_count" -gt 0 ]] && [[ "$bound_pvc_count" == "$pvc_count" ]]; then
        log_success "All persistent volumes are bound ($bound_pvc_count/$pvc_count)"
        record_result "storage_status" "PASS" "All PVCs bound"
    elif [[ "$pvc_count" -gt 0 ]]; then
        log_error "Some persistent volumes are not bound ($bound_pvc_count/$pvc_count)"
        record_result "storage_status" "FAIL" "Not all PVCs bound"
    else
        log_warning "No persistent volumes found"
        record_result "storage_status" "WARN" "No PVCs found"
    fi
}

# Validate application components
validate_application() {
    log_section "Validating Application Components"
    
    # Check main application deployment
    log_info "Checking main application deployment..."
    if kubectl get deployment provenance-linker -n "$NAMESPACE" &> /dev/null; then
        local ready_replicas=$(kubectl get deployment provenance-linker -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
        local desired_replicas=$(kubectl get deployment provenance-linker -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
        
        if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" -gt 0 ]]; then
            log_success "Main application is running ($ready_replicas/$desired_replicas replicas)"
            record_result "application_status" "PASS" "$ready_replicas/$desired_replicas replicas ready"
        else
            log_error "Main application not ready ($ready_replicas/$desired_replicas replicas)"
            record_result "application_status" "FAIL" "Not all replicas ready"
        fi
    else
        log_error "Main application deployment not found"
        record_result "application_status" "FAIL" "Deployment not found"
        return 1
    fi
    
    # Check service endpoints
    log_info "Checking service endpoints..."
    local service_endpoints=$(kubectl get endpoints provenance-linker -n "$NAMESPACE" -o jsonpath='{.subsets[0].addresses}' 2>/dev/null)
    if [[ -n "$service_endpoints" ]]; then
        local endpoint_count=$(echo "$service_endpoints" | jq length 2>/dev/null || echo 0)
        log_success "Service has $endpoint_count ready endpoints"
        record_result "service_endpoints" "PASS" "$endpoint_count endpoints ready"
    else
        log_error "No service endpoints available"
        record_result "service_endpoints" "FAIL" "No endpoints ready"
    fi
    
    # Check application health
    log_info "Checking application health..."
    local service_ip=$(kubectl get svc provenance-linker -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    if [[ -n "$service_ip" ]]; then
        if kubectl run health-check --rm -i --restart=Never --image=curlimages/curl --timeout=30s -- \
            curl -f -m 10 "http://$service_ip:8080/health" &> /dev/null; then
            log_success "Application health check passed"
            record_result "health_check" "PASS" "Health endpoint responding"
        else
            log_error "Application health check failed"
            record_result "health_check" "FAIL" "Health endpoint not responding"
        fi
    else
        log_error "Cannot determine service IP"
        record_result "health_check" "FAIL" "Service IP not available"
    fi
    
    # Check readiness probe
    log_info "Checking application readiness..."
    if kubectl run readiness-check --rm -i --restart=Never --image=curlimages/curl --timeout=30s -- \
        curl -f -m 5 "http://$service_ip:8080/ready" &> /dev/null; then
        log_success "Application readiness check passed"
        record_result "readiness_check" "PASS" "Ready endpoint responding"
    else
        log_warning "Application readiness check failed"
        record_result "readiness_check" "WARN" "Ready endpoint not responding"
    fi
    
    # Check HPA configuration
    log_info "Checking horizontal pod autoscaler..."
    if kubectl get hpa provenance-linker -n "$NAMESPACE" &> /dev/null; then
        local current_replicas=$(kubectl get hpa provenance-linker -n "$NAMESPACE" -o jsonpath='{.status.currentReplicas}')
        local desired_replicas=$(kubectl get hpa provenance-linker -n "$NAMESPACE" -o jsonpath='{.status.desiredReplicas}')
        
        log_success "HPA is configured (current: $current_replicas, desired: $desired_replicas)"
        record_result "hpa_status" "PASS" "HPA configured and active"
    else
        log_warning "Horizontal pod autoscaler not found"
        record_result "hpa_status" "WARN" "HPA not configured"
    fi
}

# Validate security configuration
validate_security() {
    log_section "Validating Security Configuration"
    
    # Check security contexts
    log_info "Checking pod security contexts..."
    local pods_with_security_context=$(kubectl get pods -n "$NAMESPACE" -l app=provenance-linker -o jsonpath='{.items[*].spec.securityContext.runAsNonRoot}' | tr ' ' '\n' | grep -c true || echo 0)
    local total_pods=$(kubectl get pods -n "$NAMESPACE" -l app=provenance-linker --no-headers | wc -l)
    
    if [[ "$pods_with_security_context" -eq "$total_pods" ]] && [[ "$total_pods" -gt 0 ]]; then
        log_success "All pods have security contexts configured"
        record_result "security_contexts" "PASS" "All pods have security context"
    else
        log_error "Some pods missing security contexts ($pods_with_security_context/$total_pods)"
        record_result "security_contexts" "FAIL" "Security contexts missing"
    fi
    
    # Check network policies
    log_info "Checking network policies..."
    if kubectl get networkpolicy -n "$NAMESPACE" &> /dev/null; then
        local policy_count=$(kubectl get networkpolicy -n "$NAMESPACE" --no-headers | wc -l)
        log_success "Network policies are configured ($policy_count policies)"
        record_result "network_policies" "PASS" "$policy_count policies found"
    else
        log_warning "No network policies found"
        record_result "network_policies" "WARN" "No network policies"
    fi
    
    # Check RBAC configuration
    log_info "Checking RBAC configuration..."
    if kubectl get serviceaccount provenance-linker -n "$NAMESPACE" &> /dev/null; then
        log_success "Service account exists"
        record_result "service_account" "PASS" "Service account configured"
        
        # Check role bindings
        if kubectl get rolebinding provenance-linker -n "$NAMESPACE" &> /dev/null; then
            log_success "Role binding exists"
            record_result "role_binding" "PASS" "Role binding configured"
        else
            log_error "Role binding not found"
            record_result "role_binding" "FAIL" "Role binding missing"
        fi
    else
        log_error "Service account not found"
        record_result "service_account" "FAIL" "Service account missing"
    fi
    
    # Check secrets
    log_info "Checking secrets configuration..."
    if kubectl get secret provenance-linker-secrets -n "$NAMESPACE" &> /dev/null; then
        local secret_keys=$(kubectl get secret provenance-linker-secrets -n "$NAMESPACE" -o jsonpath='{.data}' | jq -r 'keys[]' | wc -l)
        log_success "Application secrets are configured ($secret_keys keys)"
        record_result "secrets_config" "PASS" "$secret_keys secret keys found"
    else
        log_error "Application secrets not found"
        record_result "secrets_config" "FAIL" "Secrets missing"
    fi
    
    # Check TLS configuration
    log_info "Checking TLS configuration..."
    if kubectl get secret provenance-linker-tls -n "$NAMESPACE" &> /dev/null; then
        log_success "TLS certificates are configured"
        record_result "tls_config" "PASS" "TLS certificates found"
    else
        log_warning "TLS certificates not found"
        record_result "tls_config" "WARN" "TLS certificates missing"
    fi
}

# Validate monitoring and observability
validate_monitoring() {
    log_section "Validating Monitoring and Observability"
    
    # Check Prometheus monitoring
    log_info "Checking Prometheus monitoring..."
    if kubectl get servicemonitor provenance-linker -n "$NAMESPACE" &> /dev/null; then
        log_success "ServiceMonitor is configured"
        record_result "prometheus_monitor" "PASS" "ServiceMonitor found"
    else
        log_warning "ServiceMonitor not found"
        record_result "prometheus_monitor" "WARN" "ServiceMonitor missing"
    fi
    
    # Check metrics endpoint
    log_info "Checking metrics endpoint..."
    local service_ip=$(kubectl get svc provenance-linker -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    if [[ -n "$service_ip" ]]; then
        if kubectl run metrics-check --rm -i --restart=Never --image=curlimages/curl --timeout=30s -- \
            curl -f -m 10 "http://$service_ip:8080/metrics" &> /dev/null; then
            log_success "Metrics endpoint is accessible"
            record_result "metrics_endpoint" "PASS" "Metrics endpoint responding"
        else
            log_error "Metrics endpoint not accessible"
            record_result "metrics_endpoint" "FAIL" "Metrics endpoint not responding"
        fi
    else
        log_error "Cannot test metrics endpoint - service IP not available"
        record_result "metrics_endpoint" "FAIL" "Service IP not available"
    fi
    
    # Check log output
    log_info "Checking application logs..."
    local log_lines=$(kubectl logs deployment/provenance-linker -n "$NAMESPACE" --tail=10 2>/dev/null | wc -l)
    if [[ "$log_lines" -gt 0 ]]; then
        log_success "Application is generating logs ($log_lines recent lines)"
        record_result "logging" "PASS" "Application logging active"
    else
        log_warning "No recent log output found"
        record_result "logging" "WARN" "No recent logs"
    fi
    
    # Check for error patterns in logs
    log_info "Checking for error patterns in logs..."
    local error_count=$(kubectl logs deployment/provenance-linker -n "$NAMESPACE" --tail=100 2>/dev/null | grep -i "error\|fatal\|panic" | wc -l)
    if [[ "$error_count" -eq 0 ]]; then
        log_success "No error patterns found in recent logs"
        record_result "log_errors" "PASS" "No errors in logs"
    else
        log_warning "Found $error_count error patterns in recent logs"
        record_result "log_errors" "WARN" "$error_count errors found"
    fi
}

# Validate performance and resource usage
validate_performance() {
    log_section "Validating Performance and Resource Usage"
    
    # Check resource utilization
    log_info "Checking resource utilization..."
    if command -v kubectl &> /dev/null && kubectl top nodes &> /dev/null; then
        local cpu_usage=$(kubectl top pods -n "$NAMESPACE" -l app=provenance-linker --no-headers 2>/dev/null | awk '{sum+=$2} END {print sum}' | sed 's/m//')
        local memory_usage=$(kubectl top pods -n "$NAMESPACE" -l app=provenance-linker --no-headers 2>/dev/null | awk '{sum+=$3} END {print sum}' | sed 's/Mi//')
        
        if [[ -n "$cpu_usage" ]] && [[ -n "$memory_usage" ]]; then
            log_success "Resource usage - CPU: ${cpu_usage}m, Memory: ${memory_usage}Mi"
            record_result "resource_usage" "PASS" "CPU: ${cpu_usage}m, Memory: ${memory_usage}Mi"
        else
            log_warning "Could not retrieve resource usage metrics"
            record_result "resource_usage" "WARN" "Metrics unavailable"
        fi
    else
        log_warning "Resource metrics not available"
        record_result "resource_usage" "WARN" "kubectl top not available"
    fi
    
    # Check resource limits and requests
    log_info "Checking resource limits and requests..."
    local pods_with_limits=$(kubectl get pods -n "$NAMESPACE" -l app=provenance-linker -o jsonpath='{.items[*].spec.containers[*].resources.limits}' | wc -w)
    local pods_with_requests=$(kubectl get pods -n "$NAMESPACE" -l app=provenance-linker -o jsonpath='{.items[*].spec.containers[*].resources.requests}' | wc -w)
    
    if [[ "$pods_with_limits" -gt 0 ]] && [[ "$pods_with_requests" -gt 0 ]]; then
        log_success "Resource limits and requests are configured"
        record_result "resource_limits" "PASS" "Limits and requests configured"
    else
        log_warning "Resource limits or requests may not be configured"
        record_result "resource_limits" "WARN" "Limits/requests missing"
    fi
    
    # Check for pending pods
    log_info "Checking for pending pods..."
    local pending_pods=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase=Pending --no-headers 2>/dev/null | wc -l)
    if [[ "$pending_pods" -eq 0 ]]; then
        log_success "No pending pods found"
        record_result "pending_pods" "PASS" "No pending pods"
    else
        log_error "$pending_pods pods are in pending state"
        record_result "pending_pods" "FAIL" "$pending_pods pending pods"
    fi
}

# Run integration tests
validate_integration() {
    log_section "Running Integration Tests"
    
    # Check if test scripts exist
    if [[ -f "${PROJECT_ROOT}/test/scripts/run-tests.sh" ]]; then
        log_info "Running integration test suite..."
        
        # Run basic integration tests
        if "${PROJECT_ROOT}/test/scripts/run-tests.sh" --integration --timeout 300 &> "${VALIDATION_DIR}/integration-test.log"; then
            log_success "Integration tests passed"
            record_result "integration_tests" "PASS" "All integration tests passed"
        else
            log_error "Integration tests failed"
            record_result "integration_tests" "FAIL" "Some integration tests failed"
        fi
    else
        log_warning "Integration test script not found"
        record_result "integration_tests" "WARN" "Test script missing"
    fi
    
    # Test API connectivity
    log_info "Testing API connectivity..."
    local service_ip=$(kubectl get svc provenance-linker -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    if [[ -n "$service_ip" ]]; then
        # Test basic API endpoints
        local api_endpoints=("/health" "/ready" "/metrics")
        local successful_tests=0
        
        for endpoint in "${api_endpoints[@]}"; do
            if kubectl run api-test-${RANDOM} --rm -i --restart=Never --image=curlimages/curl --timeout=30s -- \
                curl -f -m 10 "http://$service_ip:8080$endpoint" &> /dev/null; then
                successful_tests=$((successful_tests + 1))
            fi
        done
        
        if [[ "$successful_tests" -eq "${#api_endpoints[@]}" ]]; then
            log_success "All API endpoints are accessible ($successful_tests/${#api_endpoints[@]})"
            record_result "api_connectivity" "PASS" "All endpoints accessible"
        else
            log_error "Some API endpoints are not accessible ($successful_tests/${#api_endpoints[@]})"
            record_result "api_connectivity" "FAIL" "Not all endpoints accessible"
        fi
    else
        log_error "Cannot test API connectivity - service IP not available"
        record_result "api_connectivity" "FAIL" "Service IP not available"
    fi
}

# Generate validation report
generate_validation_report() {
    if [[ "$GENERATE_REPORT" != "true" ]]; then
        return 0
    fi
    
    log_section "Generating Validation Report"
    
    local report_file="${VALIDATION_DIR}/validation-report-$(date +%Y%m%d-%H%M%S).html"
    local json_report="${VALIDATION_DIR}/validation-results.json"
    
    # Generate JSON report
    cat << EOF > "$json_report"
{
  "validation_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "namespace": "$NAMESPACE",
  "summary": {
    "total_checks": $TOTAL_CHECKS,
    "passed": $PASSED_CHECKS,
    "failed": $FAILED_CHECKS,
    "warnings": $WARNING_CHECKS,
    "success_rate": $(echo "scale=2; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc -l)
  },
  "results": {
EOF

    local first=true
    for check in "${!VALIDATION_RESULTS[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$json_report"
        fi
        
        local status=$(echo "${VALIDATION_RESULTS[$check]}" | cut -d'|' -f1)
        local details=$(echo "${VALIDATION_RESULTS[$check]}" | cut -d'|' -f2)
        
        cat << EOF >> "$json_report"
    "$check": {
      "status": "$status",
      "details": "$details"
    }
EOF
    done
    
    cat << EOF >> "$json_report"
  }
}
EOF
    
    # Generate HTML report
    cat << EOF > "$report_file"
<!DOCTYPE html>
<html>
<head>
    <title>System Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .summary { display: flex; justify-content: space-around; margin: 20px 0; }
        .metric { text-align: center; padding: 20px; border-radius: 5px; }
        .pass { background: #d4edda; color: #155724; }
        .fail { background: #f8d7da; color: #721c24; }
        .warn { background: #fff3cd; color: #856404; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .status-pass { color: #28a745; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        .status-warn { color: #ffc107; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>System Validation Report</h1>
        <p><strong>Namespace:</strong> $NAMESPACE</p>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>Validation Status:</strong> $(if [[ $FAILED_CHECKS -eq 0 ]]; then echo "✅ PASSED"; else echo "❌ FAILED"; fi)</p>
    </div>
    
    <div class="summary">
        <div class="metric pass">
            <h3>$PASSED_CHECKS</h3>
            <p>Passed</p>
        </div>
        <div class="metric fail">
            <h3>$FAILED_CHECKS</h3>
            <p>Failed</p>
        </div>
        <div class="metric warn">
            <h3>$WARNING_CHECKS</h3>
            <p>Warnings</p>
        </div>
        <div class="metric">
            <h3>$(echo "scale=1; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc -l)%</h3>
            <p>Success Rate</p>
        </div>
    </div>
    
    <h2>Detailed Results</h2>
    <table>
        <tr><th>Check</th><th>Status</th><th>Details</th></tr>
EOF

    for check in "${!VALIDATION_RESULTS[@]}"; do
        local status=$(echo "${VALIDATION_RESULTS[$check]}" | cut -d'|' -f1)
        local details=$(echo "${VALIDATION_RESULTS[$check]}" | cut -d'|' -f2)
        local status_class=""
        
        case "$status" in
            PASS) status_class="status-pass" ;;
            FAIL) status_class="status-fail" ;;
            WARN) status_class="status-warn" ;;
        esac
        
        cat << EOF >> "$report_file"
        <tr>
            <td>$check</td>
            <td class="$status_class">$status</td>
            <td>$details</td>
        </tr>
EOF
    done
    
    cat << EOF >> "$report_file"
    </table>
    
    <h2>Recommendations</h2>
    <ul>
        $(if [[ $FAILED_CHECKS -gt 0 ]]; then echo "<li>Address all failed checks before proceeding to production</li>"; fi)
        $(if [[ $WARNING_CHECKS -gt 0 ]]; then echo "<li>Review and resolve warning conditions for optimal performance</li>"; fi)
        <li>Regularly validate system health using this script</li>
        <li>Monitor application metrics and logs for ongoing health</li>
        <li>Keep security configurations up to date</li>
    </ul>
    
    <footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd;">
        <p><em>Generated by System Validation Script - $(date)</em></p>
    </footer>
</body>
</html>
EOF
    
    log_success "Validation report generated:"
    log_info "  HTML Report: $report_file"
    log_info "  JSON Results: $json_report"
}

# Print validation summary
print_summary() {
    log_section "Validation Summary"
    
    local success_rate=$(echo "scale=1; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc -l 2>/dev/null || echo "0.0")
    
    echo "=========================================="
    echo "SYSTEM VALIDATION SUMMARY"
    echo "=========================================="
    echo "Namespace: $NAMESPACE"
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Warnings: $WARNING_CHECKS"
    echo "Success Rate: ${success_rate}%"
    echo "=========================================="
    
    if [[ $FAILED_CHECKS -eq 0 ]]; then
        echo "✅ SYSTEM VALIDATION PASSED"
        echo "The system is ready for operation."
    else
        echo "❌ SYSTEM VALIDATION FAILED"
        echo "Please address the failed checks before proceeding."
        return 1
    fi
}

# Main execution function
main() {
    local check_type="all"
    
    # Parse options
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
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                set -x
                shift
                ;;
            --no-report)
                GENERATE_REPORT=false
                shift
                ;;
            --check-only)
                check_type="$2"
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
    
    log_section "Starting System Validation"
    log_info "Namespace: $NAMESPACE"
    log_info "Timeout: $TIMEOUT"
    log_info "Check Type: $check_type"
    
    # Run validation checks based on type
    case "$check_type" in
        infrastructure)
            validate_infrastructure
            ;;
        application)
            validate_application
            ;;
        security)
            validate_security
            ;;
        monitoring)
            validate_monitoring
            ;;
        performance)
            validate_performance
            ;;
        integration)
            validate_integration
            ;;
        all)
            validate_infrastructure
            validate_application  
            validate_security
            validate_monitoring
            validate_performance
            validate_integration
            ;;
        *)
            log_error "Unknown check type: $check_type"
            usage
            exit 1
            ;;
    esac
    
    # Generate report and summary
    generate_validation_report
    print_summary
}

# Run main function with all arguments
main "$@"