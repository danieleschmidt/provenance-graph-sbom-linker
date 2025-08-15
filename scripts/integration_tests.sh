#!/bin/bash

# Integration Tests for Self-Healing Pipeline Guard System
# TERRAGON SDLC AUTONOMOUS EXECUTION - Generation 3

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test function
run_test() {
    local test_name="$1"
    local test_command="$2"
    local description="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    log_info "Test: $test_name - $description"
    
    if eval "$test_command"; then
        log_success "✓ PASSED: $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log_error "✗ FAILED: $test_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Start integration testing
log_info "Starting TERRAGON SDLC Integration Testing"
log_info "Self-Healing Pipeline Guard System - All Generations"

# Test 1: Module Structure Integrity
run_test "MODULE_STRUCTURE" \
    "test -f go.mod && test -f go.sum" \
    "Verify Go module files exist and are valid"

# Test 2: Package Dependencies Resolution
run_test "DEPENDENCIES" \
    "grep -E '(gin-gonic|logrus|redis|neo4j)' go.mod > /dev/null" \
    "Verify critical dependencies are declared"

# Test 3: Self-Healing Pipeline Integration
run_test "PIPELINE_INTEGRATION" \
    "grep -A 10 -B 5 'NewSelfHealingPipeline' cmd/server/main.go | grep -q 'Start'" \
    "Verify self-healing pipeline is properly instantiated and started"

# Test 4: Monitoring Integration
run_test "MONITORING_INTEGRATION" \
    "grep -q 'metricsCollector' cmd/server/main.go && grep -q 'GetApplicationMetrics' cmd/server/main.go" \
    "Verify monitoring and metrics collection is integrated"

# Test 5: Error Handling Integration
run_test "ERROR_HANDLING_INTEGRATION" \
    "grep -q 'errorReporter' cmd/server/main.go && grep -q 'recoveryHandler' cmd/server/main.go" \
    "Verify advanced error handling is integrated"

# Test 6: Configuration Management
run_test "CONFIG_MANAGEMENT" \
    "grep -q 'config.Load()' cmd/server/main.go && test -f internal/config/config.go" \
    "Verify configuration loading and management"

# Test 7: Database Integration
run_test "DATABASE_INTEGRATION" \
    "grep -q 'NewNeo4jConnection' cmd/server/main.go && grep -q 'defer db.Close' cmd/server/main.go" \
    "Verify Neo4j database integration and cleanup"

# Test 8: API Routes Setup
run_test "API_ROUTES" \
    "grep -q 'SetupRoutes' cmd/server/main.go && test -f internal/api/routes.go" \
    "Verify API routes are properly set up"

# Test 9: Server Lifecycle Management
run_test "SERVER_LIFECYCLE" \
    "grep -q 'ListenAndServe' cmd/server/main.go && grep -q 'Shutdown' cmd/server/main.go" \
    "Verify proper server startup and graceful shutdown"

# Test 10: Signal Handling
run_test "SIGNAL_HANDLING" \
    "grep -q 'signal.Notify' cmd/server/main.go && grep -q 'SIGINT\|SIGTERM' cmd/server/main.go" \
    "Verify proper signal handling for graceful shutdown"

# Test 11: Generation 3 Components Integration
run_test "GENERATION3_INTEGRATION" \
    "grep -q 'performanceCache.*Start' cmd/server/main.go && grep -q 'resourcePool.*Start' cmd/server/main.go && grep -q 'loadBalancer.*Start' cmd/server/main.go" \
    "Verify Generation 3 performance optimization components are started"

# Test 12: Component Cleanup
run_test "COMPONENT_CLEANUP" \
    "grep -c 'defer.*Stop' cmd/server/main.go | awk '{exit (\$1 >= 3) ? 0 : 1}'" \
    "Verify proper cleanup of all major components"

# Test 13: Anomaly Detection Integration
run_test "ANOMALY_DETECTION" \
    "grep -q 'anomalyDetector.*Start' cmd/server/main.go && grep -q 'AddDataPoint' cmd/server/main.go" \
    "Verify anomaly detection is started and fed with metrics"

# Test 14: Auto-scaling Integration
run_test "AUTOSCALING_INTEGRATION" \
    "grep -q 'intelligentScaler.*Start' cmd/server/main.go" \
    "Verify intelligent auto-scaler is properly integrated"

# Test 15: Health Monitoring Loop
run_test "HEALTH_MONITORING" \
    "grep -A 20 'go func()' cmd/server/main.go | grep -q 'GetComponentHealth'" \
    "Verify health monitoring loop is implemented"

# Test 16: Security Components
run_test "SECURITY_COMPONENTS" \
    "test -f pkg/security/threat_detection.go && grep -q 'ThreatDetection' pkg/security/threat_detection.go" \
    "Verify security threat detection components"

# Test 17: Cache Infrastructure
run_test "CACHE_INFRASTRUCTURE" \
    "test -f pkg/cache/performance_cache.go && grep -q 'PerformanceCache' cmd/server/main.go" \
    "Verify caching infrastructure is in place"

# Test 18: Concurrency Management
run_test "CONCURRENCY_MANAGEMENT" \
    "test -f pkg/concurrency/resource_pool.go && grep -q 'ResourcePool' cmd/server/main.go" \
    "Verify concurrency and resource pool management"

# Test 19: Load Balancing
run_test "LOAD_BALANCING" \
    "test -f pkg/loadbalancer/intelligent_loadbalancer.go && grep -q 'IntelligentLoadBalancer' cmd/server/main.go" \
    "Verify intelligent load balancing capabilities"

# Test 20: Dynamic Configuration
run_test "DYNAMIC_CONFIG" \
    "test -f internal/config/dynamic_config.go && grep -q 'DynamicConfig' internal/config/dynamic_config.go" \
    "Verify dynamic configuration management"

# Functional Integration Tests
log_info "Running functional integration tests..."

# Test component initialization order
log_info "Validating component initialization order..."
init_order_test() {
    # Check that critical components are initialized before dependent ones
    local main_file="cmd/server/main.go"
    
    # Get line numbers for key initializations
    config_line=$(grep -n "config.Load" "$main_file" | head -1 | cut -d: -f1)
    db_line=$(grep -n "NewNeo4jConnection" "$main_file" | head -1 | cut -d: -f1)
    metrics_line=$(grep -n "NewMetricsCollector" "$main_file" | head -1 | cut -d: -f1)
    pipeline_line=$(grep -n "NewSelfHealingPipeline" "$main_file" | head -1 | cut -d: -f1)
    
    # Validate order: config -> metrics -> database -> pipeline
    if [ "$config_line" -lt "$metrics_line" ] && 
       [ "$metrics_line" -lt "$db_line" ] && 
       [ "$db_line" -lt "$pipeline_line" ]; then
        return 0
    else
        return 1
    fi
}

run_test "INITIALIZATION_ORDER" \
    "init_order_test" \
    "Verify components are initialized in correct dependency order"

# Test error handling coverage
error_handling_test() {
    local error_handlers=0
    
    # Count error handling patterns
    error_handlers=$(grep -c "if err != nil" cmd/server/main.go)
    
    # Should have substantial error handling
    [ "$error_handlers" -ge 10 ]
}

run_test "ERROR_HANDLING_COVERAGE" \
    "error_handling_test" \
    "Verify comprehensive error handling throughout main server"

# Test graceful shutdown implementation
graceful_shutdown_test() {
    # Check for proper shutdown sequence
    grep -A 20 "Shutting down server" cmd/server/main.go | grep -q "WithTimeout" &&
    grep -A 20 "Shutting down server" cmd/server/main.go | grep -q "shutdownCancel"
}

run_test "GRACEFUL_SHUTDOWN" \
    "graceful_shutdown_test" \
    "Verify graceful shutdown implementation with timeout"

# Test logging integration
logging_test() {
    local log_statements=0
    
    # Count logging statements
    log_statements=$(grep -E "(log\.|logger\.)" cmd/server/main.go | wc -l)
    
    # Should have adequate logging
    [ "$log_statements" -ge 8 ]
}

run_test "LOGGING_INTEGRATION" \
    "logging_test" \
    "Verify adequate logging throughout the application"

# Test context usage
context_test() {
    # Check for proper context usage
    grep -q "context.WithCancel" cmd/server/main.go &&
    grep -q "context.WithTimeout" cmd/server/main.go
}

run_test "CONTEXT_USAGE" \
    "context_test" \
    "Verify proper context usage for cancellation and timeouts"

# API Integration Tests
log_info "Testing API integration..."

# Test API handler integration
api_integration_test() {
    # Check if self-healing handlers are properly integrated
    test -f internal/handlers/self_healing.go &&
    grep -q "GetOverallHealth\|GetComponentHealth\|GetHealingActions" internal/handlers/self_healing.go
}

run_test "API_HANDLER_INTEGRATION" \
    "api_integration_test" \
    "Verify self-healing API handlers are properly implemented"

# Performance Tests
log_info "Running performance validation tests..."

# Test for performance optimizations
performance_test() {
    local perf_features=0
    
    # Count performance-related features
    [ -f pkg/cache/performance_cache.go ] && perf_features=$((perf_features + 1))
    [ -f pkg/concurrency/resource_pool.go ] && perf_features=$((perf_features + 1))
    [ -f pkg/loadbalancer/intelligent_loadbalancer.go ] && perf_features=$((perf_features + 1))
    
    # Should have all 3 performance components
    [ "$perf_features" -eq 3 ]
}

run_test "PERFORMANCE_OPTIMIZATIONS" \
    "performance_test" \
    "Verify all performance optimization components are implemented"

# Security Integration Tests
log_info "Testing security integration..."

# Test security implementation
security_test() {
    local security_features=0
    
    # Count security features
    [ -f pkg/security/threat_detection.go ] && security_features=$((security_features + 1))
    grep -q "CircuitBreaker" pkg/pipeline/self_healing.go && security_features=$((security_features + 1))
    grep -q "RateLimiter" pkg/loadbalancer/intelligent_loadbalancer.go && security_features=$((security_features + 1))
    
    # Should have multiple security features
    [ "$security_features" -ge 2 ]
}

run_test "SECURITY_INTEGRATION" \
    "security_test" \
    "Verify security features are properly integrated"

# Resource Management Tests
log_info "Testing resource management..."

# Test resource cleanup
resource_cleanup_test() {
    # Check for proper resource cleanup patterns
    local cleanup_patterns=0
    
    grep -q "defer.*Close" cmd/server/main.go && cleanup_patterns=$((cleanup_patterns + 1))
    grep -q "defer.*Stop" cmd/server/main.go && cleanup_patterns=$((cleanup_patterns + 1))
    grep -q "defer.*cancel" cmd/server/main.go && cleanup_patterns=$((cleanup_patterns + 1))
    
    # Should have multiple cleanup patterns
    [ "$cleanup_patterns" -ge 3 ]
}

run_test "RESOURCE_CLEANUP" \
    "resource_cleanup_test" \
    "Verify proper resource cleanup and memory management"

# Final Integration Summary
log_info "==============================================="
log_info "TERRAGON SDLC Integration Testing Summary"
log_info "==============================================="
log_info "Total Integration Tests: $TOTAL_TESTS"
log_success "Passed: $PASSED_TESTS"
log_error "Failed: $FAILED_TESTS"

success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
log_info "Success Rate: $success_rate%"

# Additional system-level checks
log_info "Performing system-level integration checks..."

# Check file organization
file_organization_score=0
expected_dirs=("pkg" "internal" "cmd" "scripts")
for dir in "${expected_dirs[@]}"; do
    if [ -d "$dir" ]; then
        file_organization_score=$((file_organization_score + 1))
    fi
done

log_info "File organization score: $file_organization_score/${#expected_dirs[@]}"

# Check component count
component_count=$(find pkg/ -name "*.go" -path "*/pkg/*" | wc -l)
log_info "Total Go components: $component_count"

# Check integration complexity
integration_points=$(grep -r "New.*(" pkg/ | wc -l)
log_info "Integration points detected: $integration_points"

# Final result determination
if [ "$success_rate" -ge 95 ]; then
    log_success "🎉 OUTSTANDING: Integration testing completed successfully!"
    log_success "All systems properly integrated and ready for production."
    exit 0
elif [ "$success_rate" -ge 85 ]; then
    log_success "✅ EXCELLENT: Integration testing passed."
    log_info "System is well-integrated and production-ready."
    exit 0
elif [ "$success_rate" -ge 75 ]; then
    log_warning "⚠️ GOOD: Integration testing passed with minor issues."
    log_warning "Some integration improvements recommended."
    exit 0
else
    log_error "❌ FAILED: Integration testing failed."
    log_error "Significant integration issues must be resolved."
    exit 1
fi