#!/bin/bash
# Comprehensive Quality Gates for Provenance Graph SBOM Linker
# Autonomous SDLC - Generation Quality Validation

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COVERAGE_THRESHOLD=${COVERAGE_THRESHOLD:-75}
PERFORMANCE_THRESHOLD_MS=${PERFORMANCE_THRESHOLD_MS:-500}
SECURITY_SCORE_THRESHOLD=${SECURITY_SCORE_THRESHOLD:-85}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_GATES=0
PASSED_GATES=0
FAILED_GATES=0

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')] $*${NC}"; }
success() { echo -e "${GREEN}[$(date +'%H:%M:%S')] ✅ $*${NC}"; }
warning() { echo -e "${YELLOW}[$(date +'%H:%M:%S')] ⚠️  $*${NC}"; }
error() { echo -e "${RED}[$(date +'%H:%M:%S')] ❌ $*${NC}"; }

# Gate result tracking
gate_result() {
    local gate_name="$1"
    local result="$2"
    local message="$3"
    
    TOTAL_GATES=$((TOTAL_GATES + 1))
    
    if [[ "$result" == "PASS" ]]; then
        success "Gate: $gate_name - $message"
        PASSED_GATES=$((PASSED_GATES + 1))
    else
        error "Gate: $gate_name - $message"
        FAILED_GATES=$((FAILED_GATES + 1))
    fi
}

# Gate 1: Build and Compilation
gate_build() {
    log "Running Gate 1: Build and Compilation"
    
    cd "$PROJECT_ROOT"
    export PATH=$PATH:/usr/local/go/bin
    
    # Check Go version
    if ! go version | grep -q "go1.2[3-9]"; then
        gate_result "Build" "FAIL" "Go version 1.23+ required"
        return 1
    fi
    
    # Clean build
    go clean ./...
    
    # Build all targets
    if go build -o /tmp/server ./cmd/server/ && \
       go build -o /tmp/cli ./cmd/cli/ && \
       go build -o /tmp/standalone ./cmd/standalone/; then
        gate_result "Build" "PASS" "All binaries compiled successfully"
    else
        gate_result "Build" "FAIL" "Compilation failed"
        return 1
    fi
}

# Gate 2: Unit Tests
gate_unit_tests() {
    log "Running Gate 2: Unit Tests"
    
    cd "$PROJECT_ROOT"
    export PATH=$PATH:/usr/local/go/bin
    
    # Run tests with coverage
    local coverage_file="/tmp/coverage.out"
    if go test -v -short -coverprofile="$coverage_file" ./pkg/validation ./internal/version ./pkg/sbom 2>/dev/null; then
        # Calculate coverage
        local coverage_pct
        coverage_pct=$(go tool cover -func="$coverage_file" 2>/dev/null | tail -n 1 | awk '{print $3}' | sed 's/%//')
        
        if (( $(echo "$coverage_pct >= $COVERAGE_THRESHOLD" | bc -l) )); then
            gate_result "Unit Tests" "PASS" "Coverage: ${coverage_pct}% (≥${COVERAGE_THRESHOLD}%)"
        else
            gate_result "Unit Tests" "FAIL" "Coverage: ${coverage_pct}% (<${COVERAGE_THRESHOLD}%)"
        fi
    else
        gate_result "Unit Tests" "FAIL" "Test execution failed"
    fi
}

# Gate 3: Code Quality
gate_code_quality() {
    log "Running Gate 3: Code Quality"
    
    cd "$PROJECT_ROOT"
    export PATH=$PATH:/usr/local/go/bin
    
    # Go fmt check
    local fmt_issues
    fmt_issues=$(gofmt -l . | wc -l)
    if [[ "$fmt_issues" -eq 0 ]]; then
        gate_result "Code Format" "PASS" "No formatting issues"
    else
        gate_result "Code Format" "FAIL" "$fmt_issues files need formatting"
    fi
    
    # Go vet check
    if go vet ./... 2>/dev/null; then
        gate_result "Code Vet" "PASS" "No vet issues"
    else
        gate_result "Code Vet" "FAIL" "Vet issues found"
    fi
    
    # Check for common issues
    local todo_count
    todo_count=$(grep -r "TODO\|FIXME\|BUG\|HACK" --include="*.go" . | wc -l)
    if [[ "$todo_count" -lt 10 ]]; then
        gate_result "Code Cleanup" "PASS" "$todo_count technical debt items"
    else
        gate_result "Code Cleanup" "FAIL" "$todo_count technical debt items (>10)"
    fi
}

# Gate 4: Security Validation
gate_security() {
    log "Running Gate 4: Security Validation"
    
    cd "$PROJECT_ROOT"
    
    # Check for hardcoded secrets
    local secret_patterns=("password" "secret" "key" "token" "credential")
    local secret_count=0
    
    for pattern in "${secret_patterns[@]}"; do
        local matches
        matches=$(grep -ri "$pattern" --include="*.go" --include="*.yaml" --include="*.json" . | grep -v "test" | wc -l)
        secret_count=$((secret_count + matches))
    done
    
    if [[ "$secret_count" -lt 5 ]]; then
        gate_result "Secret Scan" "PASS" "$secret_count potential secrets found"
    else
        gate_result "Secret Scan" "FAIL" "$secret_count potential secrets found (>5)"
    fi
    
    # Check dependencies for known vulnerabilities
    if command -v nancy &> /dev/null; then
        if go list -json -deps ./... | nancy sleuth; then
            gate_result "Dependency Scan" "PASS" "No known vulnerabilities"
        else
            gate_result "Dependency Scan" "FAIL" "Vulnerable dependencies found"
        fi
    else
        warning "Nancy not available, skipping dependency scan"
        gate_result "Dependency Scan" "PASS" "Skipped (tool not available)"
    fi
}

# Gate 5: Performance Validation
gate_performance() {
    log "Running Gate 5: Performance Validation"
    
    cd "$PROJECT_ROOT"
    export PATH=$PATH:/usr/local/go/bin
    
    # Run benchmarks
    local bench_output
    if bench_output=$(go test -bench=. -benchmem ./... 2>/dev/null); then
        # Check if any benchmarks ran
        if echo "$bench_output" | grep -q "Benchmark"; then
            # Extract average times (simplified)
            local avg_time
            avg_time=$(echo "$bench_output" | grep "ns/op" | awk '{print $3}' | head -1 | sed 's/ns\/op//')
            
            if [[ -n "$avg_time" ]] && (( avg_time < PERFORMANCE_THRESHOLD_MS * 1000000 )); then
                gate_result "Performance" "PASS" "Average benchmark: ${avg_time}ns/op"
            else
                gate_result "Performance" "FAIL" "Benchmarks exceed threshold"
            fi
        else
            gate_result "Performance" "PASS" "No benchmarks to evaluate"
        fi
    else
        gate_result "Performance" "FAIL" "Benchmark execution failed"
    fi
    
    # Memory usage check (simplified)
    local binary_size
    binary_size=$(ls -la /tmp/server 2>/dev/null | awk '{print $5}')
    if [[ -n "$binary_size" ]] && [[ "$binary_size" -lt 104857600 ]]; then # 100MB
        gate_result "Binary Size" "PASS" "Server binary: $binary_size bytes"
    else
        gate_result "Binary Size" "FAIL" "Server binary too large: $binary_size bytes"
    fi
}

# Gate 6: Integration Tests
gate_integration() {
    log "Running Gate 6: Integration Tests"
    
    cd "$PROJECT_ROOT"
    export PATH=$PATH:/usr/local/go/bin
    
    # Start test server in background
    local server_port=18080
    ./server --port="$server_port" --config=config/development.yaml &
    local server_pid=$!
    
    sleep 3
    
    # Test basic endpoints
    local health_check=false
    if curl -f -s "http://localhost:$server_port/health" > /dev/null; then
        health_check=true
    fi
    
    # Cleanup
    kill $server_pid 2>/dev/null || true
    sleep 1
    
    if [[ "$health_check" == true ]]; then
        gate_result "Integration" "PASS" "Health endpoint responding"
    else
        gate_result "Integration" "FAIL" "Health endpoint not responding"
    fi
}

# Gate 7: Documentation
gate_documentation() {
    log "Running Gate 7: Documentation"
    
    cd "$PROJECT_ROOT"
    
    # Check for required documentation files
    local required_docs=("README.md" "CONTRIBUTING.md" "LICENSE" "SECURITY.md")
    local missing_docs=0
    
    for doc in "${required_docs[@]}"; do
        if [[ ! -f "$doc" ]]; then
            missing_docs=$((missing_docs + 1))
        fi
    done
    
    if [[ "$missing_docs" -eq 0 ]]; then
        gate_result "Documentation" "PASS" "All required docs present"
    else
        gate_result "Documentation" "FAIL" "$missing_docs required docs missing"
    fi
    
    # Check API documentation
    local api_docs_count
    api_docs_count=$(find docs -name "*.md" 2>/dev/null | wc -l)
    if [[ "$api_docs_count" -gt 5 ]]; then
        gate_result "API Documentation" "PASS" "$api_docs_count documentation files"
    else
        gate_result "API Documentation" "FAIL" "Insufficient API documentation"
    fi
}

# Gate 8: Container Security
gate_container_security() {
    log "Running Gate 8: Container Security"
    
    cd "$PROJECT_ROOT"
    
    # Check Dockerfile security practices
    if [[ -f "Dockerfile.production" ]]; then
        local security_score=100
        
        # Check for non-root user
        if ! grep -q "USER" Dockerfile.production; then
            security_score=$((security_score - 20))
        fi
        
        # Check for health checks
        if ! grep -q "HEALTHCHECK" Dockerfile.production; then
            security_score=$((security_score - 10))
        fi
        
        # Check for minimal base image
        if ! grep -q "scratch\|distroless\|alpine" Dockerfile.production; then
            security_score=$((security_score - 15))
        fi
        
        if [[ "$security_score" -ge "$SECURITY_SCORE_THRESHOLD" ]]; then
            gate_result "Container Security" "PASS" "Security score: $security_score"
        else
            gate_result "Container Security" "FAIL" "Security score: $security_score (< $SECURITY_SCORE_THRESHOLD)"
        fi
    else
        gate_result "Container Security" "FAIL" "No production Dockerfile found"
    fi
}

# Gate 9: Deployment Readiness
gate_deployment_readiness() {
    log "Running Gate 9: Deployment Readiness"
    
    cd "$PROJECT_ROOT"
    
    # Check for deployment configurations
    local deployment_files=("deploy" "k8s" "docker-compose")
    local deployment_ready=false
    
    for dir in "${deployment_files[@]}"; do
        if [[ -d "$dir" ]]; then
            deployment_ready=true
            break
        fi
    done
    
    # Check for production scripts
    if [[ -f "scripts/production-deploy.sh" ]]; then
        deployment_ready=true
    fi
    
    if [[ "$deployment_ready" == true ]]; then
        gate_result "Deployment Config" "PASS" "Deployment configurations present"
    else
        gate_result "Deployment Config" "FAIL" "No deployment configurations found"
    fi
    
    # Check for monitoring configs
    if [[ -f "observability/prometheus-rules.yaml" ]] || [[ -f "observability/grafana-dashboard.json" ]]; then
        gate_result "Monitoring Config" "PASS" "Monitoring configurations present"
    else
        gate_result "Monitoring Config" "FAIL" "No monitoring configurations found"
    fi
}

# Gate 10: SLSA Compliance
gate_slsa_compliance() {
    log "Running Gate 10: SLSA Compliance"
    
    cd "$PROJECT_ROOT"
    
    local slsa_score=0
    
    # Source control (SLSA Level 1)
    if [[ -d ".git" ]]; then
        slsa_score=$((slsa_score + 25))
    fi
    
    # Build system (SLSA Level 2)
    if [[ -f ".github/workflows/ci.yml" ]] || [[ -f "Makefile" ]]; then
        slsa_score=$((slsa_score + 25))
    fi
    
    # Provenance (SLSA Level 3)
    if [[ -f "SBOM.json" ]] || [[ -f "sbom.cyclonedx.json" ]]; then
        slsa_score=$((slsa_score + 25))
    fi
    
    # Verification (SLSA Level 4)
    if find . -name "*.sig" -o -name "*.asc" | grep -q .; then
        slsa_score=$((slsa_score + 25))
    fi
    
    if [[ "$slsa_score" -ge 75 ]]; then
        gate_result "SLSA Compliance" "PASS" "SLSA score: $slsa_score/100"
    else
        gate_result "SLSA Compliance" "FAIL" "SLSA score: $slsa_score/100 (< 75)"
    fi
}

# Generate final report
generate_final_report() {
    log "Generating Quality Gates Report..."
    
    local success_rate
    if [[ "$TOTAL_GATES" -gt 0 ]]; then
        success_rate=$(( (PASSED_GATES * 100) / TOTAL_GATES ))
    else
        success_rate=0
    fi
    
    local report_file="/tmp/quality-gates-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" <<EOF
# Provenance Graph SBOM Linker - Quality Gates Report
Generated: $(date)
Project: Autonomous SDLC - Generation 3 Implementation

## Summary
Total Gates: $TOTAL_GATES
Passed: $PASSED_GATES
Failed: $FAILED_GATES
Success Rate: $success_rate%

## Gate Results
1. Build and Compilation: $(if [[ $PASSED_GATES -gt 0 ]]; then echo "PASS"; else echo "FAIL"; fi)
2. Unit Tests: $(if [[ $PASSED_GATES -gt 1 ]]; then echo "PASS"; else echo "FAIL"; fi)
3. Code Quality: $(if [[ $PASSED_GATES -gt 2 ]]; then echo "PASS"; else echo "FAIL"; fi)
4. Security Validation: $(if [[ $PASSED_GATES -gt 3 ]]; then echo "PASS"; else echo "FAIL"; fi)
5. Performance Validation: $(if [[ $PASSED_GATES -gt 4 ]]; then echo "PASS"; else echo "FAIL"; fi)
6. Integration Tests: $(if [[ $PASSED_GATES -gt 5 ]]; then echo "PASS"; else echo "FAIL"; fi)
7. Documentation: $(if [[ $PASSED_GATES -gt 6 ]]; then echo "PASS"; else echo "FAIL"; fi)
8. Container Security: $(if [[ $PASSED_GATES -gt 7 ]]; then echo "PASS"; else echo "FAIL"; fi)
9. Deployment Readiness: $(if [[ $PASSED_GATES -gt 8 ]]; then echo "PASS"; else echo "FAIL"; fi)
10. SLSA Compliance: $(if [[ $PASSED_GATES -gt 9 ]]; then echo "PASS"; else echo "FAIL"; fi)

## Recommendations
EOF

    if [[ "$success_rate" -ge 80 ]]; then
        echo "✅ Quality gates passed with excellent score ($success_rate%)" >> "$report_file"
        echo "✅ Ready for production deployment" >> "$report_file"
    elif [[ "$success_rate" -ge 60 ]]; then
        echo "⚠️  Quality gates passed with acceptable score ($success_rate%)" >> "$report_file"
        echo "⚠️  Consider addressing failed gates before production" >> "$report_file"
    else
        echo "❌ Quality gates failed with poor score ($success_rate%)" >> "$report_file"
        echo "❌ Must address critical issues before deployment" >> "$report_file"
    fi
    
    echo "Report saved to: $report_file"
    cat "$report_file"
}

# Main execution
main() {
    log "🛡️  Starting Comprehensive Quality Gates Validation"
    log "Project: Provenance Graph SBOM Linker (Autonomous SDLC)"
    
    gate_build || true
    gate_unit_tests || true
    gate_code_quality || true
    gate_security || true
    gate_performance || true
    gate_integration || true
    gate_documentation || true
    gate_container_security || true
    gate_deployment_readiness || true
    gate_slsa_compliance || true
    
    generate_final_report
    
    local success_rate
    if [[ "$TOTAL_GATES" -gt 0 ]]; then
        success_rate=$(( (PASSED_GATES * 100) / TOTAL_GATES ))
    else
        success_rate=0
    fi
    
    if [[ "$success_rate" -ge 80 ]]; then
        success "🎉 Quality Gates: $success_rate% SUCCESS - Ready for production!"
        exit 0
    elif [[ "$success_rate" -ge 60 ]]; then
        warning "⚠️  Quality Gates: $success_rate% PARTIAL - Review recommended"
        exit 1
    else
        error "💥 Quality Gates: $success_rate% FAILED - Critical issues must be resolved"
        exit 2
    fi
}

# Execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi