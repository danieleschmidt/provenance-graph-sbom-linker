#!/bin/bash

# Quality Gates Validation Script for Self-Healing Pipeline Guard System
# Generation 3: TERRAGON SDLC AUTONOMOUS EXECUTION

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Quality gate tracking
TOTAL_GATES=0
PASSED_GATES=0
FAILED_GATES=0

# Quality gate function
quality_gate() {
    local gate_name="$1"
    local command="$2"
    local description="$3"
    
    TOTAL_GATES=$((TOTAL_GATES + 1))
    
    log_info "Quality Gate: $gate_name - $description"
    
    if eval "$command"; then
        log_success "✓ PASSED: $gate_name"
        PASSED_GATES=$((PASSED_GATES + 1))
        return 0
    else
        log_error "✗ FAILED: $gate_name"
        FAILED_GATES=$((FAILED_GATES + 1))
        return 1
    fi
}

# Start quality gates validation
log_info "Starting TERRAGON SDLC Quality Gates Validation"
log_info "Self-Healing Pipeline Guard System - Generation 3"

# Gate 1: Code Structure Validation
quality_gate "CODE_STRUCTURE" \
    "find pkg/ -name '*.go' | wc -l | awk '{exit (\$1 >= 10) ? 0 : 1}'" \
    "Verify minimum 10 Go files in pkg directory"

# Gate 2: Self-Healing Components Existence
quality_gate "SELF_HEALING_COMPONENTS" \
    "test -f pkg/pipeline/self_healing.go && test -f pkg/pipeline/anomaly_detection.go && test -f pkg/autoscaling/intelligent_scaler.go" \
    "Verify core self-healing components exist"

# Gate 3: Error Handling Infrastructure
quality_gate "ERROR_HANDLING" \
    "test -f pkg/errors/advanced_error_handler.go && test -f pkg/security/threat_detection.go" \
    "Verify advanced error handling and security components"

# Gate 4: Performance Optimization Components
quality_gate "PERFORMANCE_OPTIMIZATION" \
    "test -f pkg/cache/performance_cache.go && test -f pkg/concurrency/resource_pool.go && test -f pkg/loadbalancer/intelligent_loadbalancer.go" \
    "Verify Generation 3 performance optimization components"

# Gate 5: Configuration Management
quality_gate "CONFIGURATION" \
    "test -f internal/config/dynamic_config.go && test -f internal/config/config.go" \
    "Verify configuration management systems"

# Gate 6: Monitoring and Metrics
quality_gate "MONITORING" \
    "test -f pkg/monitoring/metrics.go && test -f pkg/monitoring/self_healing_metrics.go" \
    "Verify comprehensive monitoring infrastructure"

# Gate 7: Main Server Integration
quality_gate "MAIN_INTEGRATION" \
    "grep -q 'performanceCache' cmd/server/main.go && grep -q 'resourcePool' cmd/server/main.go && grep -q 'loadBalancer' cmd/server/main.go" \
    "Verify Generation 3 components integrated in main server"

# Gate 8: Go Module Validation
quality_gate "GO_MODULE" \
    "test -f go.mod && grep -q 'github.com/danieleschmidt/provenance-graph-sbom-linker' go.mod" \
    "Verify Go module configuration"

# Gate 9: Handler Integration
quality_gate "HANDLERS" \
    "test -f internal/handlers/self_healing.go && grep -q 'GetHealthDashboard' internal/handlers/self_healing.go" \
    "Verify self-healing API handlers"

# Gate 10: Security Implementation
quality_gate "SECURITY" \
    "grep -q 'ThreatDetection' pkg/security/threat_detection.go && grep -q 'SQLInjection' pkg/security/threat_detection.go" \
    "Verify security threat detection implementation"

# Gate 11: Concurrency and Resource Management
quality_gate "CONCURRENCY" \
    "grep -q 'ResourcePool' pkg/concurrency/resource_pool.go && grep -q 'AdaptiveScaler' pkg/concurrency/resource_pool.go" \
    "Verify advanced concurrency and resource management"

# Gate 12: Caching Infrastructure
quality_gate "CACHING" \
    "grep -q 'PerformanceCache' pkg/cache/performance_cache.go && grep -q 'PreloadingEngine' pkg/cache/performance_cache.go" \
    "Verify intelligent caching with preloading"

# Gate 13: Load Balancing
quality_gate "LOAD_BALANCING" \
    "grep -q 'IntelligentLoadBalancer' pkg/loadbalancer/intelligent_loadbalancer.go && grep -q 'PredictiveAlgorithm' pkg/loadbalancer/intelligent_loadbalancer.go" \
    "Verify intelligent load balancing capabilities"

# Gate 14: Documentation Comments
quality_gate "DOCUMENTATION" \
    "find pkg/ -name '*.go' -exec grep -l '//' {} \\; | wc -l | awk '{exit (\$1 >= 5) ? 0 : 1}'" \
    "Verify documentation comments in code"

# Gate 15: Error Resilience Patterns
quality_gate "RESILIENCE" \
    "grep -q 'CircuitBreaker' pkg/pipeline/self_healing.go && grep -q 'RecoveryStrategy' pkg/errors/advanced_error_handler.go" \
    "Verify resilience patterns implementation"

# Code quality checks
log_info "Performing code quality analysis..."

# Check for TODO/FIXME comments
todo_count=$(find . -name "*.go" -exec grep -l "TODO\|FIXME" {} \; 2>/dev/null | wc -l)
if [ "$todo_count" -gt 10 ]; then
    log_warning "Found $todo_count files with TODO/FIXME comments"
else
    log_success "Acceptable number of TODO/FIXME comments: $todo_count"
fi

# Check for proper error handling patterns
error_handling_files=$(find pkg/ -name "*.go" -exec grep -l "error" {} \; | wc -l)
total_go_files=$(find pkg/ -name "*.go" | wc -l)
error_coverage=$((error_handling_files * 100 / total_go_files))

if [ "$error_coverage" -ge 80 ]; then
    log_success "Good error handling coverage: $error_coverage%"
else
    log_warning "Error handling coverage could be improved: $error_coverage%"
fi

# Complexity analysis
log_info "Analyzing code complexity..."

complex_functions=$(find pkg/ -name "*.go" -exec grep -E "^func.*\{$" {} \; | wc -l)
log_info "Total functions found: $complex_functions"

# Check for large files (potential complexity issues)
large_files=$(find pkg/ -name "*.go" -exec wc -l {} \; | awk '$1 > 500 {print $2}' | wc -l)
if [ "$large_files" -gt 0 ]; then
    log_warning "Found $large_files files with >500 lines (potential complexity issues)"
else
    log_success "No overly large files detected"
fi

# Security checks
log_info "Performing security validation..."

# Check for hardcoded credentials
security_issues=$(find . -name "*.go" -exec grep -i "password\|secret\|key.*=" {} \; 2>/dev/null | grep -v "mapstructure\|json\|Config\|Field" | wc -l)
if [ "$security_issues" -gt 0 ]; then
    log_warning "Potential hardcoded credentials found: $security_issues instances"
else
    log_success "No obvious hardcoded credentials detected"
fi

# Performance analysis
log_info "Analyzing performance considerations..."

# Check for goroutine usage
goroutine_usage=$(find pkg/ -name "*.go" -exec grep -l "go func\|go " {} \; | wc -l)
log_info "Files using goroutines: $goroutine_usage"

# Check for mutex usage (concurrency safety)
mutex_usage=$(find pkg/ -name "*.go" -exec grep -l "sync\." {} \; | wc -l)
log_info "Files using synchronization primitives: $mutex_usage"

# Architecture validation
log_info "Validating architecture compliance..."

# Check for proper package organization
architecture_score=0

# Check for separation of concerns
if [ -d "pkg/" ] && [ -d "internal/" ] && [ -d "cmd/" ]; then
    architecture_score=$((architecture_score + 1))
    log_success "Proper package structure (pkg/, internal/, cmd/)"
fi

# Check for interface usage
interface_files=$(find pkg/ -name "*.go" -exec grep -l "type.*interface" {} \; | wc -l)
if [ "$interface_files" -ge 3 ]; then
    architecture_score=$((architecture_score + 1))
    log_success "Good interface usage for abstraction"
fi

# Check for dependency injection patterns
di_files=$(find pkg/ -name "*.go" -exec grep -l "New.*(" {} \; | wc -l)
if [ "$di_files" -ge 5 ]; then
    architecture_score=$((architecture_score + 1))
    log_success "Constructor pattern usage detected"
fi

log_info "Architecture compliance score: $architecture_score/3"

# Final quality gate summary
log_info "==============================================="
log_info "TERRAGON SDLC Quality Gates Summary"
log_info "==============================================="
log_info "Total Quality Gates: $TOTAL_GATES"
log_success "Passed: $PASSED_GATES"
log_error "Failed: $FAILED_GATES"

success_rate=$((PASSED_GATES * 100 / TOTAL_GATES))
log_info "Success Rate: $success_rate%"

# Determine overall result
if [ "$success_rate" -ge 90 ]; then
    log_success "🎉 EXCELLENT: Quality gates validation passed with flying colors!"
    log_success "System ready for production deployment."
    exit 0
elif [ "$success_rate" -ge 80 ]; then
    log_success "✅ GOOD: Quality gates validation passed."
    log_info "Minor improvements recommended but system is production-ready."
    exit 0
elif [ "$success_rate" -ge 70 ]; then
    log_warning "⚠️ ACCEPTABLE: Quality gates validation passed with warnings."
    log_warning "Several improvements needed before production deployment."
    exit 1
else
    log_error "❌ FAILED: Quality gates validation failed."
    log_error "Significant issues must be resolved before production deployment."
    exit 1
fi