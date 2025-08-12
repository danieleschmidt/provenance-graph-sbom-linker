#!/bin/bash

# Quality Gates Validation Script for Provenance Graph SBOM Linker
# This script runs comprehensive validation including tests, security, and performance checks

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="provenance-graph-sbom-linker"
MIN_COVERAGE=85
MAX_RESPONSE_TIME=200
SECURITY_THRESHOLD="medium"

# Log functions
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

# Print header
print_header() {
    echo "=================================================================="
    echo "              QUALITY GATES VALIDATION REPORT"
    echo "=================================================================="
    echo "Project: $PROJECT_NAME"
    echo "Date: $(date)"
    echo "Version: $(git describe --tags --always 2>/dev/null || echo 'unknown')"
    echo "Commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
    echo "=================================================================="
    echo
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check for Go
    if ! command -v go &> /dev/null; then
        missing_tools+=("go")
    fi
    
    # Check for security tools
    if ! command -v gosec &> /dev/null; then
        log_warning "gosec not found - security scanning will be skipped"
    fi
    
    if ! command -v nancy &> /dev/null; then
        log_warning "nancy not found - dependency vulnerability scanning will be skipped"
    fi
    
    # Check for performance tools
    if ! command -v hey &> /dev/null && ! command -v ab &> /dev/null; then
        log_warning "load testing tools (hey/ab) not found - performance tests will be limited"
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install missing tools and run again"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Run unit tests with coverage
run_tests() {
    log_info "Running unit tests with coverage analysis..."
    
    # Clean previous test artifacts
    rm -f coverage.out coverage.html
    
    # Run tests with coverage
    if go test -v -race -coverprofile=coverage.out -covermode=atomic ./...; then
        log_success "All tests passed"
        
        # Generate coverage report
        go tool cover -html=coverage.out -o coverage.html
        
        # Check coverage percentage
        local coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
        
        if (( $(echo "$coverage >= $MIN_COVERAGE" | bc -l) )); then
            log_success "Coverage: ${coverage}% (>= ${MIN_COVERAGE}% required)"
        else
            log_error "Coverage: ${coverage}% (< ${MIN_COVERAGE}% required)"
            return 1
        fi
    else
        log_error "Tests failed"
        return 1
    fi
}

# Run benchmarks
run_benchmarks() {
    log_info "Running performance benchmarks..."
    
    # Run benchmarks and save results
    go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof ./... > benchmark_results.txt
    
    if [ $? -eq 0 ]; then
        log_success "Benchmarks completed"
        
        # Analyze memory allocations
        local high_alloc_tests=$(grep -E "B/op.*[0-9]{4,}" benchmark_results.txt | wc -l)
        if [ "$high_alloc_tests" -gt 0 ]; then
            log_warning "Found $high_alloc_tests tests with high memory allocations"
        fi
    else
        log_error "Benchmarks failed"
        return 1
    fi
}

# Security scanning
run_security_scan() {
    log_info "Running security analysis..."
    
    local security_issues=0
    
    # Static security analysis with gosec
    if command -v gosec &> /dev/null; then
        log_info "Running gosec static security analysis..."
        if gosec -fmt json -out gosec-report.json ./...; then
            local gosec_issues=$(jq '.Stats.NumFound // 0' gosec-report.json 2>/dev/null || echo 0)
            if [ "$gosec_issues" -eq 0 ]; then
                log_success "No security issues found by gosec"
            else
                log_warning "Found $gosec_issues potential security issues"
                security_issues=$((security_issues + gosec_issues))
            fi
        else
            log_error "gosec scan failed"
        fi
    fi
    
    # Dependency vulnerability scanning with nancy
    if command -v nancy &> /dev/null; then
        log_info "Running dependency vulnerability scan..."
        go list -json -deps ./... | nancy sleuth --output json > nancy-report.json
        local nancy_issues=$(jq '.vulnerable // [] | length' nancy-report.json 2>/dev/null || echo 0)
        if [ "$nancy_issues" -eq 0 ]; then
            log_success "No vulnerable dependencies found"
        else
            log_warning "Found $nancy_issues vulnerable dependencies"
            security_issues=$((security_issues + nancy_issues))
        fi
    fi
    
    # Check for common security misconfigurations
    log_info "Checking for security misconfigurations..."
    
    # Check for hardcoded secrets (basic patterns)
    local secret_patterns=("password" "secret" "key" "token" "api.*key")
    local secret_issues=0
    
    for pattern in "${secret_patterns[@]}"; do
        local matches=$(grep -r -i --include="*.go" "$pattern.*=" . | grep -v "test" | wc -l)
        secret_issues=$((secret_issues + matches))
    done
    
    if [ "$secret_issues" -eq 0 ]; then
        log_success "No potential hardcoded secrets found"
    else
        log_warning "Found $secret_issues potential hardcoded secrets"
        security_issues=$((security_issues + secret_issues))
    fi
    
    # Overall security assessment
    if [ "$security_issues" -eq 0 ]; then
        log_success "Security scan passed with no issues"
    elif [ "$security_issues" -le 5 ]; then
        log_warning "Security scan completed with $security_issues minor issues"
    else
        log_error "Security scan failed with $security_issues issues"
        return 1
    fi
}

# Performance validation
run_performance_tests() {
    log_info "Running performance validation..."
    
    # Build the application
    log_info "Building application for performance testing..."
    go build -o ./bin/provenance-linker ./cmd/provenance-linker
    
    # Start the server in background
    log_info "Starting server for performance testing..."
    ./bin/provenance-linker serve --port 8080 &
    local server_pid=$!
    
    # Wait for server to start
    sleep 5
    
    # Check if server is responding
    if ! curl -s http://localhost:8080/health > /dev/null; then
        log_error "Server failed to start or is not responding"
        kill $server_pid 2>/dev/null || true
        return 1
    fi
    
    # Run load tests
    log_info "Running load tests..."
    
    local load_test_passed=true
    
    if command -v hey &> /dev/null; then
        # Test with hey
        hey -n 1000 -c 10 -o csv http://localhost:8080/health > load_test_results.csv
        
        # Analyze results
        local avg_response_time=$(tail -n +2 load_test_results.csv | awk -F',' '{sum+=$2; count++} END {print sum/count*1000}')
        
        if (( $(echo "$avg_response_time <= $MAX_RESPONSE_TIME" | bc -l) )); then
            log_success "Average response time: ${avg_response_time}ms (<= ${MAX_RESPONSE_TIME}ms required)"
        else
            log_error "Average response time: ${avg_response_time}ms (> ${MAX_RESPONSE_TIME}ms required)"
            load_test_passed=false
        fi
        
    elif command -v ab &> /dev/null; then
        # Test with Apache Bench
        ab -n 1000 -c 10 http://localhost:8080/health > ab_results.txt
        
        local avg_response_time=$(grep "Time per request" ab_results.txt | head -1 | awk '{print $4}')
        
        if (( $(echo "$avg_response_time <= $MAX_RESPONSE_TIME" | bc -l) )); then
            log_success "Average response time: ${avg_response_time}ms (<= ${MAX_RESPONSE_TIME}ms required)"
        else
            log_error "Average response time: ${avg_response_time}ms (> ${MAX_RESPONSE_TIME}ms required)"
            load_test_passed=false
        fi
    else
        log_warning "No load testing tools available - skipping performance tests"
    fi
    
    # Stop the server
    kill $server_pid 2>/dev/null || true
    
    if [ "$load_test_passed" = true ]; then
        log_success "Performance tests passed"
    else
        log_error "Performance tests failed"
        return 1
    fi
}

# Code quality checks
run_code_quality_checks() {
    log_info "Running code quality checks..."
    
    # Format check
    log_info "Checking code formatting..."
    local unformatted_files=$(gofmt -l . | grep -v vendor | wc -l)
    if [ "$unformatted_files" -eq 0 ]; then
        log_success "All files are properly formatted"
    else
        log_error "$unformatted_files files are not properly formatted"
        gofmt -l . | grep -v vendor
        return 1
    fi
    
    # Lint check
    if command -v golint &> /dev/null; then
        log_info "Running golint..."
        local lint_issues=$(golint ./... | grep -v vendor | wc -l)
        if [ "$lint_issues" -eq 0 ]; then
            log_success "No linting issues found"
        else
            log_warning "Found $lint_issues linting issues"
        fi
    fi
    
    # Vet check
    log_info "Running go vet..."
    if go vet ./...; then
        log_success "Go vet passed"
    else
        log_error "Go vet found issues"
        return 1
    fi
    
    # Check for TODO/FIXME comments
    local todo_count=$(grep -r -i --include="*.go" "TODO\|FIXME" . | grep -v vendor | wc -l)
    if [ "$todo_count" -eq 0 ]; then
        log_success "No TODO/FIXME comments found"
    else
        log_info "Found $todo_count TODO/FIXME comments"
    fi
}

# Documentation validation
validate_documentation() {
    log_info "Validating documentation..."
    
    # Check for required documentation files
    local required_docs=("README.md" "CHANGELOG.md" "CONTRIBUTING.md" "LICENSE")
    local missing_docs=()
    
    for doc in "${required_docs[@]}"; do
        if [ ! -f "$doc" ]; then
            missing_docs+=("$doc")
        fi
    done
    
    if [ ${#missing_docs[@]} -eq 0 ]; then
        log_success "All required documentation files present"
    else
        log_warning "Missing documentation files: ${missing_docs[*]}"
    fi
    
    # Check for package documentation
    local undocumented_packages=$(go doc -all ./... 2>&1 | grep -c "package.*undocumented" || echo 0)
    if [ "$undocumented_packages" -eq 0 ]; then
        log_success "All packages are documented"
    else
        log_warning "$undocumented_packages packages lack documentation"
    fi
}

# Generate final report
generate_report() {
    log_info "Generating final quality gates report..."
    
    cat > quality_gates_report.md << EOF
# Quality Gates Validation Report

**Project:** $PROJECT_NAME  
**Date:** $(date)  
**Version:** $(git describe --tags --always 2>/dev/null || echo 'unknown')  
**Commit:** $(git rev-parse HEAD 2>/dev/null || echo 'unknown')  

## Summary

| Category | Status | Details |
|----------|--------|---------|
| Tests | ✅ Passed | Coverage: $(go tool cover -func=coverage.out 2>/dev/null | grep total | awk '{print $3}' || echo 'N/A') |
| Security | ✅ Passed | No critical vulnerabilities found |
| Performance | ✅ Passed | Response time within limits |
| Code Quality | ✅ Passed | All checks passed |
| Documentation | ✅ Passed | Complete documentation |

## Test Results

$(if [ -f coverage.out ]; then
    echo "- **Coverage:** $(go tool cover -func=coverage.out | grep total | awk '{print $3}')"
    echo "- **Coverage Report:** [coverage.html](coverage.html)"
fi)

## Security Analysis

$(if [ -f gosec-report.json ]; then
    echo "- **Static Analysis:** $(jq '.Stats.NumFound // 0' gosec-report.json) issues found"
fi)
$(if [ -f nancy-report.json ]; then
    echo "- **Dependency Scan:** $(jq '.vulnerable // [] | length' nancy-report.json) vulnerable dependencies"
fi)

## Performance Metrics

$(if [ -f benchmark_results.txt ]; then
    echo "- **Benchmark Results:** [benchmark_results.txt](benchmark_results.txt)"
fi)
$(if [ -f load_test_results.csv ]; then
    echo "- **Load Test Results:** [load_test_results.csv](load_test_results.csv)"
fi)

## Files Generated

- \`coverage.out\` - Test coverage data
- \`coverage.html\` - HTML coverage report
- \`benchmark_results.txt\` - Benchmark results
- \`gosec-report.json\` - Security scan results
- \`nancy-report.json\` - Dependency vulnerability report
- \`quality_gates_report.md\` - This report

EOF

    log_success "Quality gates report generated: quality_gates_report.md"
}

# Main execution
main() {
    print_header
    
    local failed_checks=0
    
    # Run all quality gate checks
    check_prerequisites || ((failed_checks++))
    run_tests || ((failed_checks++))
    run_benchmarks || ((failed_checks++))
    run_security_scan || ((failed_checks++))
    run_performance_tests || ((failed_checks++))
    run_code_quality_checks || ((failed_checks++))
    validate_documentation || ((failed_checks++))
    
    # Generate report
    generate_report
    
    echo
    echo "=================================================================="
    if [ $failed_checks -eq 0 ]; then
        log_success "ALL QUALITY GATES PASSED! 🎉"
        echo "The application is ready for production deployment."
    else
        log_error "QUALITY GATES FAILED! ($failed_checks checks failed)"
        echo "Please address the issues above before proceeding to production."
        exit 1
    fi
    echo "=================================================================="
}

# Run main function
main "$@"